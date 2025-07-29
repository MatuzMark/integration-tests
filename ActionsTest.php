<?php

declare(strict_types=1);

namespace Tests\Controllers;

use App\Test\MockTOTP;
use CodeIgniter\Config\Factories;
use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Actions\ActionInterface;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Test\AuthenticationTesting;
use CodeIgniter\Test\DatabaseTestTrait;
use CodeIgniter\Test\FeatureTestTrait;
use Config\Services;
use Opten\User\Actions\TOTPActivator;
use Opten\User\Authenticators\TOTP;
use Opten\User\Config\Auth;
use Opten\User\Enums\UserGroupType;
use PragmaRX\Google2FA\Google2FA;
use Tests\Support\DatabaseTestCase;
use Tests\Support\FakeUser;

/**
 * @internal
 */
final class ActionsTest extends DatabaseTestCase
{
    use DatabaseTestTrait;
    use FeatureTestTrait;
    use AuthenticationTesting;
    use FakeUser;

    private const URL_2FA = '/users/2fa/hitelesites';

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure our actions are registered with the system
        $config                      = config(Auth::class);
        $config->actions['login']    = TOTPActivator::class;
        $config->actions['register'] = TOTPActivator::class;
        Factories::injectMock('config', 'Auth', $config);

        // Add auth routes
        $routes = service('routes');
        auth()->routes($routes, ['except' => ['register', 'login', 'magic-link', 'logout', 'auth-actions']]);
        Services::injectMock('routes', $routes);

        // @phpstan-ignore-next-line
        $_SESSION = [];

        $this->user->createEmailIdentity(['email' => 'integration-test@test.com', 'password' => 'Secret123*']);
    }

    public function testActionShowNoneAvailable(): void
    {
        $this->expectException(PageNotFoundException::class);

        $result = $this->withSession([])->get(self::URL_2FA);

        // Nothing found, it should die gracefully.
        $result->assertStatus(404);
    }

    public function testTotp2FAShow(): void
    {
        $this->insertIdentityTotp2FA();

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->get(self::URL_2FA);

        $result->assertStatus(200);

        $result->assertSee(lang('TOTP.title2FA'));
        $result->assertSee(lang('TOTP.confirmCode'));
        $result->assertSeeInField('token', '');
        $result->assertSeeElement('input[type=submit]');

        $result->assertSessionMissing('error');
        $result->assertSessionMissing('errors');

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $this->user->id,
            'type'    => TOTP::ID_TYPE_TOTP_2FA,
            'name'    => TOTP::ID_TYPE_TOTP_2FA,
        ]);
    }

    public function testActionHandleDisabled(): void
    {
        $this->expectException(PageNotFoundException::class);

        $result = $this->withSession([])->get('/auth/a/handle');

        // Nothing found, it should die gracefully.
        $result->assertStatus(404);
    }

    public function testTotp2FAVerifySyntaxInvalidToken(): void
    {
        $this->insertIdentityTotp2FA();

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->withHeaders([csrf_header() => csrf_hash()])
            ->post(self::URL_2FA, [
                'token' => 'invalid-token',
            ]);

        $result->assertRedirectTo(url_to('auth-action-show'));
        $result->assertSessionHas('error', lang('Auth.invalid2FAToken'));
    }

    public function testTotp2FAVerifyInvalidToken(): void
    {
        $this->insertIdentityTotp2FA();

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->withHeaders([csrf_header() => csrf_hash()])
            ->post(self::URL_2FA, [
                'token' => '234567',
            ]);

        $result->assertRedirectTo(url_to('auth-action-show'));
        $result->assertSessionHas('error', lang('Auth.invalid2FAToken'));
    }

    public function testTotp2FAVerifySuccessWithSupplier(): void
    {
        $this->totp2FAVerifySuccess(UserGroupType::Supplier);
    }

    public function testTotp2FAVerifySuccessWithPartner(): void
    {
        $this->totp2FAVerifySuccess(UserGroupType::Partner);
    }

    public function testTotp2FAVerifySuccessWithAdmin(): void
    {
        $this->totp2FAVerifySuccess(UserGroupType::OptenAdmin);
    }

    public function testTotp2FACannotBeBypassed(): void
    {
        $this->insertIdentityTotp2FA();

        // Try to visit a "logged-in" page, skipping the 2FA
        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->get('/ugyfel/profil');

        $result->assertRedirectTo(url_to('auth-action-show'));
    }

    public function testTotp2FAShowWithQRCodeForNewUser(): void
    {
        $this->user->deactivate();

        $totp          = Services::totp();
        $totpSecretKey = $totp->generateSecretKey();

        $this->insertIdentityTotp2FA($totpSecretKey);

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->get(self::URL_2FA);

        $result->assertStatus(200);
        $result->assertSee(lang('TOTP.title2FA'));
        $result->assertSeeElement('svg.totp-qrcode');
        $result->assertSee(lang('TOTP.problems', ['placeholder' => $totpSecretKey]));
        $result->assertSeeInField('token', '');
        $result->assertSeeElement('input[type=submit]');
    }

    public function testTotp2FAShowWithoutQRCodeForExistingUser(): void
    {
        $this->insertIdentityTotp2FA();

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->get(self::URL_2FA);

        $result->assertStatus(200);
        $result->assertSee(lang('TOTP.title2FA'));
        $result->assertSee(lang('TOTP.confirmCode'));
        $result->assertSee(lang('RecoveryCodes.TOTP.troubleTitle'));
        $result->assertSee(lang('RecoveryCodes.TOTP.troubleGoto', ['link' => url_to('recovery-code-show')]));
        $result->assertDontSee(lang('TOTP.googleApp', [
            'android' => lang('TOTP.android'),
            'ios'     => lang('TOTP.ios'),
        ]));
        $result->assertDontSeeElement('svg.totp-qrcode');
    }

    private function totp2FAVerifySuccess(UserGroupType $userGroupType): void
    {
        $this->insertIdentityTotp2FA();

        Services::injectMock('totp', new MockTOTP(new Google2FA()));

        $this->user->addGroup($userGroupType->value);

        $result = $this->actingAs($this->user, true)
            ->withSession($this->getSessionUserInfo())
            ->withHeaders([csrf_header() => csrf_hash()])
            ->post(self::URL_2FA, [
                'token' => '123456',
            ]);

        $result->assertRedirectTo(config(Auth::class)->loginRedirect());

        $result->assertSessionMissing('auth_action');
        $result->assertSessionMissing('auth_action_message');
        $result->assertSessionMissing('error');
        $result->assertSessionMissing('errors');

        // the totp_2fa identity shouldn't be removed
        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $this->user->id,
            'type'    => TOTP::ID_TYPE_TOTP_2FA,
        ]);
    }

    /**
     * @return array{user: array{id: int, auth_action: class-string<ActionInterface>}}
     */
    private function getSessionUserInfo(string $class = TOTPActivator::class): array
    {
        return [
            'user' => [
                'id'          => $this->user->id,
                'auth_action' => $class,
            ],
        ];
    }

    private function insertIdentityTotp2FA(?string $totpSecretKey = null): void
    {
        $totp = Services::totp();
        $totpSecretKey ??= $totp->generateSecretKey();

        $encryptedSecretKey = Services::encrypter()->encrypt($totpSecretKey);

        // Ensures it's outside the current time window, so the user can use TOTP immediately
        $lastUsedAt = Time::yesterday();

        // An identity with 2FA info would have been stored previously
        $identities = model(UserIdentityModel::class);
        $identities->insert([
            'user_id'      => $this->user->id,
            'type'         => TOTP::ID_TYPE_TOTP_2FA,
            'name'         => TOTP::ID_TYPE_TOTP_2FA,
            'secret'       => $encryptedSecretKey,
            'last_used_at' => $lastUsedAt,
            'extra'        => lang('Auth.need2FA'),
        ]);
    }
}
