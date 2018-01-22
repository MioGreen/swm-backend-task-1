<?php

namespace SailWithMe\Services\Facebook;

use Auth;
use Carbon\Carbon;
use Facebook\Exceptions\FacebookResponseException;
use Facebook\Exceptions\FacebookSDKException;
use SailWithMe\Exceptions\FacebookServiceException;
use SailWithMe\Repositories\Mongo\UserRepository;
use SailWithMe\Services\UserService;

class FacebookService
{
    /**
     * @var FacebookClient|\Facebook\Facebook
     */
    private $client;

    /**
     * @var UserService
     */
    private $userService;

    /**
     * @var UserRepository
     */
    private $userRepository;

    public function __construct(FacebookClient $client, UserService $userService, UserRepository $userRepository)
    {
        $this->client = $client;
        $this->userService = $userService;
        $this->userRepository = $userRepository;
    }

    public function login(string $accessToken): string
    {
        try {
            $fields = ['email', 'birthday', 'gender', 'first_name', 'short_name', 'last_name', 'middle_name'];
            $fieldsUri = 'fields=' . implode(',', $fields);
            $response = $this->client->get('me?' . $fieldsUri, $accessToken);
            $userData = $response->getDecodedBody();

            return $this->findOrCreateUserToken($userData);
        } catch (FacebookResponseException $e) {
            \Log::error(
                "Facebook graph API error: " . $e->getMessage(),
                ['code' => $e->getCode(), 'trace' => $e->getTrace()]
            );
            throw new FacebookServiceException("Facebook graph API error: " . $e->getMessage(), $e->getCode());
        } catch (FacebookSDKException $e) {
            \Log::error(
                "Facebook SDK error: " . $e->getMessage(),
                ['code' => $e->getCode(), 'trace' => $e->getTrace()]
            );
            throw new FacebookServiceException("Facebook SDK error: " . $e->getMessage(), $e->getCode());
        }

    }

    private function findOrCreateUserToken(array $userData): string
    {
        $user = $this->userRepository->findByFacebookId($userData['id']);

        if (!$user) {
            $user = $this->userRepository->findByEmail($userData['email']);

            if (!$user) {
                $password = str_random(16);
                $email = $userData['email'];

                $alias = $userData['short_name'] ?? $userData['first_name'] . ' ' . $userData['last_name'];

                $user = $this->userService->create($email, $password, $alias);
            } else {
                Auth::login($user);
            }

            if (isset($userData['gender'])) {
                $gender = $userData['gender'] == 'male' ? 1 : 2;
            }

            $alias = $userData['short_name'] ?? $userData['first_name'] . ' ' . $userData['last_name'];

            if (isset($userData['birthday'])) {
                $birthday = Carbon::createFromFormat('m/d/Y', $userData['birthday'])->toDateString();
            } else {
                $birthday = null;
            }

            $additionalUserData = [
                'first_name' => $userData['first_name'] ?? null,
                'last_name' => $userData['last_name'] ?? null,
                'middle_name' => $userData['middle_name'] ?? null,
                'birthday' => $birthday,
                'gender' => $gender ?? null,
                'alias' => $alias,
            ];

            $userProperties = [
                'fb_id' => $userData['id'],
                'social_register' => true,
                'adult' => true,
            ];

            $user = $this->userService->setUserData($user, $additionalUserData);
            $user = $this->userService->setUserProperties($user, $userProperties);
        } else {
            Auth::login($user);
        }

        return $this->userService->getAuthTokenFromUser($user);
    }
}