<?php

namespace Bloatless\Endocore\Components\BasicAuth\Tests\Unit;

use Bloatless\Endocore\Components\BasicAuth\BasicAuth;
use Bloatless\Endocore\Components\BasicAuth\Factory;
use PHPUnit\Framework\TestCase;

class FactoryTest extends TestCase
{
    public function testFactoryWithValidConfig()
    {
        $config = [
            'auth' => [
                'users' => [
                    'foo' => '$2y$10$hJpespHOJUYzFtHIQk57OusBdwIOXz.8tUdbb9j545Meh2wmeshMm',
                ]
            ]
        ];

        $factory = new Factory($config);
        $auth = $factory->makeAuth();
        $this->assertInstanceOf(BasicAuth::class, $auth);
    }

    public function testFactoryWithInvalidConfig()
    {
        $config = [];
        $factory = new Factory($config);
        $auth = $factory->makeAuth();
        $this->assertInstanceOf(BasicAuth::class, $auth);
    }
}
