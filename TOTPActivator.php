<?php

declare(strict_types=1);

namespace Opten\User\Actions;

use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\Response;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Actions\ActionInterface;
use CodeIgniter\Shield\Entities\User as ShieldUser;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use CodeIgniter\Shield\Models\UserIdentityModel;
use Config\Services;
use Opten\User\Authenticators\TOTP;
use Opten\User\Config\Auth;
use Opten\User\Config\TOTP as TOTPConfig;
use Opten\User\Entities\User;

class TOTPActivator implements ActionInterface
{
    private string $type = TOTP::ID_TYPE_TOTP_2FA;

    /**
     * Shows the initial screen to the user with a QR code for activation
     */
    public function show(): string
    {
        /** @var TOTP $authenticator */
        $authenticator = auth('totp')->getAuthenticator();

        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new RuntimeException('Cannot get the pending login User.');
        }

        $viewData = [];

        if ($user->isNotActivated() || $user->requiresReset($this->type)) {
            $identity = $this->getIdentity($user);

            $totp   = Services::totp();
            $secret = Services::encrypter()->decrypt($identity->secret);
            $issuer = config(TOTPConfig::class)->issuer;
            $QRCode = $totp->generateQRCode($issuer, $user->username, $secret);

            $viewData = ['QRCode' => $QRCode, 'secret' => $secret];
        }

        return view(setting('Auth.views')['action-totp-2fa-show'], $viewData);
    }

    /**
     * This method is unused.
     *
     * @return Response|string
     */
    public function handle(IncomingRequest $request)
    {
        throw new PageNotFoundException();
    }

    /**
     * Verifies the QR code matches an
     * identity we have for that user.
     *
     * @return RedirectResponse
     */
    public function verify(IncomingRequest $request)
    {
        /** @var TOTP $authenticator */
        $authenticator = auth('totp')->getAuthenticator();

        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new RuntimeException('Cannot get the pending login User.');
        }

        $isNotActivated = $user->isNotActivated();

        $token = $request->getPost('token');

        $validator = Services::validation();

        if (! $validator->check($token, 'required|exact_length[6]|is_natural')) {
            $error = lang($isNotActivated ? 'Auth.invalidActivateToken' : 'Auth.invalid2FAToken');

            return redirect('auth-action-show')->with('error', $error);
        }

        $identity = $this->getIdentity($user);

        // No match - let them try again.
        if (! $authenticator->checkAction($identity, $token)) {
            $error = lang($isNotActivated ? 'Auth.invalidActivateToken' : 'Auth.invalid2FAToken');

            return redirect('auth-action-show')->with('error', $error);
        }

        $config = config(Auth::class);

        if ($isNotActivated) {
            $user->activate();

            return redirect()->to($config->registerRedirect());
        }

        $user->undoForceReset($this->type);

        return redirect()->to($config->loginRedirect());
    }

    /**
     * Creates a TOTP identity for the action of the user if don't have yet.
     *
     * Called after a successful signup OR login.
     */
    public function createIdentity(ShieldUser $user): string
    {
        $identityModel = model(UserIdentityModel::class);

        $identity = $identityModel->getIdentityByType($user, $this->type);

        // we have 2fa identity (after signup), do not create another one
        if ($identity !== null) {
            return $identity->secret;
        }

        /** @var User $user */
        return $this->create2FAIdentity($user);
    }

    private function create2FAIdentity(User $user): string
    {
        $totp          = Services::totp();
        $totpSecretKey = $totp->generateSecretKey();

        $encryptedSecretKey = Services::encrypter()->encrypt($totpSecretKey);

        // Ensures it's outside the current time window, so the user can use TOTP immediately
        $lastUsedAt = Time::yesterday();

        return model(UserIdentityModel::class)->createCodeIdentity(
            $user,
            [
                'type'         => $this->type,
                'name'         => $this->type,
                'last_used_at' => $lastUsedAt,
                'extra'        => lang('Auth.need2FA'),
            ],
            static fn (): string => $encryptedSecretKey
        );
    }

    /**
     * Returns an identity for the action of the user.
     */
    private function getIdentity(User $user): ?UserIdentity
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getIdentityByType(
            $user,
            $this->type
        );
    }

    /**
     * Returns the string type of the action class.
     */
    public function getType(): string
    {
        return $this->type;
    }
}
