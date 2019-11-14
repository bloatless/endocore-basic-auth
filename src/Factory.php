<?php

declare(strict_types=1);

namespace Bloatless\Endocore\Components\BasicAuth;

class Factory
{
    /**
     * @var array $authConfig
     */
    protected $authConfig = [];

    public function __construct(array $config)
    {
        $this->authConfig = $config['auth'] ?? [];
    }

    /**
     * Creates and returns basic-auth object.
     *
     * @return BasicAuth
     */
    public function makeAuth(): BasicAuth
    {
        $users = $this->authConfig['users'] ?? [];

        return new BasicAuth($users);
    }
}
