<?php

namespace Bloatless\Endocore\Components\BasicAuth\Tests\Unit;

use Bloatless\Endocore\Components\BasicAuth\BasicAuth;
use Bloatless\Endocore\Http\Request;
use Bloatless\Endocore\Http\Response;
use PHPUnit\Framework\TestCase;

class BasicAuthTest extends TestCase
{
    protected $config;

    public function setUp(): void
    {
        $this->config = [
            'auth' => [
                'users' => [
                    'foo' => '$2y$10$hJpespHOJUYzFtHIQk57OusBdwIOXz.8tUdbb9j545Meh2wmeshMm',
                ]
            ]
        ];
    }

    public function testGetSetUsers()
    {
        // set via config
        $auth = new BasicAuth($this->config['auth']['users']);
        $users = $auth->getUsers();
        $this->assertIsArray($users);
        $this->assertArrayHasKey('foo', $users);
        $this->assertEquals($this->config['auth']['users']['foo'], $users['foo']);

        // set via setter
        $auth = new BasicAuth;
        $this->assertEquals([], $auth->getUsers());
        $auth->setUsers($this->config['auth']['users']);
        $users = $auth->getUsers();
        $this->assertArrayHasKey('foo', $users);
        $this->assertEquals($this->config['auth']['users']['foo'], $users['foo']);
    }

    public function testIsAuthenticatedWithoutHTTPHeader()
    {
        // test without auth header
        $auth = new BasicAuth;
        $request = new Request;
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);
    }

    public function testIsAuthenticatedWithValidHttpHeader()
    {
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('foo:bar'),
        ]);
        $auth = new BasicAuth;
        $auth->setUsers($this->config['auth']['users']);
        $result = $auth->isAuthenticated($request);
        $this->assertTrue($result);
    }

    public function testIsAuthenticatedWithInvalidHttpHeader()
    {
        $auth = new BasicAuth;

        // Header is missing "Basic" keyword
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'cisaB ' . base64_encode('foo:bar'),
        ]);
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);

        // Header with invalid base64 encoding
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'Basic FooBarBz',
        ]);
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);
    }

    public function testIsAuthenticatedWithNoUsersSet()
    {
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('foo:bar'),
        ]);
        $auth = new BasicAuth;
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);

    }

    public function testIsAuthenticatedWithInvalidUsername()
    {
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('invalid:bar'),
        ]);
        $auth = new BasicAuth;
        $auth->setUsers($this->config['auth']['users']);
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);
    }

    public function testIsAuthenticatedWithInvalidPassword()
    {
        $request = new Request([], [], [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('foo:naa'),
        ]);
        $auth = new BasicAuth;
        $auth->setUsers($this->config['auth']['users']);
        $result = $auth->isAuthenticated($request);
        $this->assertFalse($result);
    }

    public function testRequestAuthorization()
    {
        $auth = new BasicAuth;
        $response = $auth->requestAuthorization();
        $this->assertInstanceOf(Response::class, $response);
        $this->assertEquals(401, $response->getStatus());

        $headers = $response->getHeaders();
        $this->assertIsArray($headers);
        $this->assertEquals([
            'WWW-Authenticate' => 'Basic realm="Restricted access"',
        ], $headers);
    }
}
