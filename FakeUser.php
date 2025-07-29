<?php

declare(strict_types=1);

namespace Tests\Support;

use Opten\User\Entities\User;
use Opten\User\Models\User as UserModel;

trait FakeUser
{
    private ?User $user = null;

    protected function setUpFakeUser(): void
    {
        $this->user = fake(UserModel::class);
    }

    protected function tearDownFakeUser(): void
    {
        // we should create a migration to delete fake users, but for now we just delete it.
        // TODO: create valid migration
        model(UserModel::class)->delete($this->user->id, true);
    }
}
