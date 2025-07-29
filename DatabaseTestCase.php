<?php

declare(strict_types=1);

namespace Tests\Support;

use CodeIgniter\Test\DatabaseTestTrait;
use Opten\User\Config\Auth;

/**
 * @internal
 */
abstract class DatabaseTestCase extends TestCase
{
    use DatabaseTestTrait;

    // protected $namespace = '\CodeIgniter\Shield'; // inherited: 'Tests\Support'
    protected $migrate = false; // turn off currently

    /**
     * Auth Table names
     *
     * @var array<string, string>
     */
    protected array $tables;

    protected function setUp(): void
    {
        parent::setUp();

        $authConfig   = config(Auth::class);
        $this->tables = $authConfig->tables;
    }
}
