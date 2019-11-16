<?php

namespace Bloatless\Endocore\Components\BasicAuth;

use Bloatless\Endocore\Http\Request;
use Bloatless\Endocore\Http\Response;

class BasicAuth
{
    /**
     * Valid/known users.
     * Username as array key and password-hash as value.
     *
     * @var array $users
     */
    protected $users = [];

    public function __construct(array $users = [])
    {
        $this->setUsers($users);
    }

    /**
     * Sets valid/known users.
     *
     * @param array $users
     */
    public function setUsers(array $users): void
    {
        $this->users = $users;
    }

    /**
     * Returns valid/known users.
     *
     * @return array
     */
    public function getUsers(): array
    {
        return $this->users;
    }

    /**
     * Checks if given request is authenticated.
     *
     * @param Request $request
     * @return bool
     */
    public function isAuthenticated(Request $request): bool
    {
        $credentials = $this->getCredentialsFromRequest($request);
        if (empty($credentials['username']) || empty($credentials['password'])) {
            return false;
        }

        return $this->validateCredentials($credentials['username'], $credentials['password']);
    }

    /**
     * Returns a response requesting authentication.
     *
     * @return Response
     */
    public function requestAuthorization(): Response
    {
        $response = new Response(401, [
            'WWW-Authenticate' => 'Basic realm="Restricted access"',
        ]);

        return $response;
    }

    /**
     * Parses authorization header and returns credentials.
     *
     * @param Request $request
     * @return array
     */
    protected function getCredentialsFromRequest(Request $request): array
    {
        $credentials = [
            'username' => null,
            'password' => null,
        ];

        // Check if authentication header is present
        $authHeader = $request->getServerParam('HTTP_AUTHORIZATION');
        if (empty($authHeader)) {
            return $credentials;
        }

        // Check if authentication header is valid
        $authHeaderParts = explode(' ', $authHeader);
        if ($authHeaderParts[0] !== 'Basic') {
            return $credentials;
        }

        // Collect and return credentials
        $userPass = base64_decode($authHeaderParts[1]);
        if (strpos($userPass, ':') === false) {
            return $credentials;
        }
        $colonPos = strpos($userPass, ':');
        $credentials['username'] = trim(substr($userPass, 0, $colonPos));
        $credentials['password'] = trim(substr($userPass, $colonPos + 1));

        return $credentials;
    }

    /**
     * Checks if given credentials are valid.
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    protected function validateCredentials(string $username, string $password): bool
    {
        if (empty($this->users)) {
            return false;
        }

        if (!isset($this->users[$username])) {
            return false;
        }

        $knowHash = $this->users[$username];

        return password_verify($password, $knowHash);
    }
}
