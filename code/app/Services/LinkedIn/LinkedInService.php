<?php

namespace SailWithMe\Services\LinkedIn;

use GuzzleHttp\Client as GuzzleClient;
use Happyr\LinkedIn\LinkedIn;
use Http\Adapter\Guzzle6\Client;
use Http\Message\MessageFactory\GuzzleMessageFactory;
use Ramsey\Uuid\Uuid;
use SailWithMe\Exceptions\LinkedInServiceException;
use SailWithMe\Repositories\LinkedInTemporaryAuthDataRepository;
use SailWithMe\Repositories\Mongo\UserRepository;
use SailWithMe\Services\UserService;

class LinkedInService
{
    const AUTH_URL = 'https://www.linkedin.com/oauth/v2/authorization';

    const ACCESS_TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken';

    /**
     * @var LinkedInTemporaryAuthDataRepository
     */
    private $authDataRepository;

    /**
     * @var UserRepository
     */
    private $userRepository;

    /**
     * @var UserService
     */
    private $userService;

    public function __construct(
        LinkedInTemporaryAuthDataRepository $authDataRepository,
        UserRepository $userRepository,
        UserService $userService
    ) {
        $this->client = new LinkedIn(config('linkedin.app-id'), config('linkedin.secret'));
        $this->client->setHttpClient(new Client());
        $this->client->setHttpMessageFactory(new GuzzleMessageFactory());
        $this->authDataRepository = $authDataRepository;
        $this->userRepository = $userRepository;
        $this->userService = $userService;
    }

    public function getLoginUrl(string $returnLink = null): string
    {
        if (!$returnLink) {
            $returnLink = config('app.ft_url');
        }

        $entity = $this->authDataRepository->create([
            'uuid' => Uuid::uuid4()->toString(),
            'return_link' => $returnLink
        ]);
        $urlData = [
            'response_type' => 'code',
            'client_id' => config('linkedin.app-id'),
            'redirect_uri' => secure_url('/api/v1/auth/ln_login'),
            'state' => $entity->uuid,
        ];
        $url = self::AUTH_URL . '?' . http_build_query($urlData);

        return $url;
    }

    public function getAccessTokenAndReturnLink(string $requestCode, string $checkState): array
    {
        $entity = $this->authDataRepository->findByUuid($checkState);

        if (!$entity) {
            throw new LinkedInServiceException("User with this state not found", 401);
        }

        $url = self::ACCESS_TOKEN_URL;
        $requestData = [
            'grant_type' => 'authorization_code',
            'code' => $requestCode,
            'redirect_uri' => secure_url('/api/v1/auth/ln_login'),
            'client_id' => config('linkedin.app-id'),
            'client_secret' => config('linkedin.secret'),
        ];
        $client = new GuzzleClient();
        $response = $client->request('POST', $url, ['form_params' => $requestData]);
        $data = json_decode($response->getBody()->getContents(), true);
        $accessToken = $data['access_token'];

        $this->client->setAccessToken($accessToken);
        $linkedInUserData = $this->client->get('v1/people/~:(id,first-name,last-name,email-address)');

        return [
            'token' => $this->authUserViaLinkedIn($linkedInUserData),
            'return_link' => $entity->return_link
        ];
    }

    private function authUserViaLinkedIn($linkedInUserData)
    {
        $email = $linkedInUserData['emailAddress'];
        $firstName = $linkedInUserData['firstName'];
        $lastName = $linkedInUserData['lastName'];
        $id = $linkedInUserData['id'];
        $alias = $firstName . ' ' . $lastName;
        $password = str_random(12);
        $user = $this->userRepository->findByLinkedInId($id);

        if (!$user) {
            $user = $this->userRepository->findByEmail($email);

            if (!$user) {
                $additionalUserData = [
                    'first_name' => $firstName ?? null,
                    'last_name' => $lastName ?? null,
                ];
                $userProperties = [
                    'ln_id' => $id,
                    'social_register' => true,
                    'adult' => true,
                ];
                $user = $this->userService->create($email, $password, $alias);
                $user = $this->userService->setUserProperties($user, $additionalUserData);
                $user = $this->userService->setUserData($user, $userProperties);

                return $this->userService->getAuthTokenFromUser($user);
            } else {
                $userProperties = [
                    'ln_id' => $id,
                    'social_register' => true,
                    'adult' => true,
                ];
                $user = $this->userService->setUserProperties($user, $userProperties);

                return $this->userService->getAuthTokenFromUser($user);
            }
        }

        return $this->userService->getAuthTokenFromUser($user);
    }
}