<?php

namespace SailWithMe\Http\Controllers\Api;


use Auth;
use JWTAuth;

use Validator;

use Illuminate\Http\Request;
use SailWithMe\Constants\ErrorCodes;
use SailWithMe\Services\UserService;
use SailWithMe\Exceptions\BaseException;
use Tymon\JWTAuth\Exceptions\JWTException;
use SailWithMe\Http\Requests\RegisterRequest;
use Illuminate\Validation\ValidationException;
use SailWithMe\Services\Facebook\FacebookService;
use SailWithMe\Services\LinkedIn\LinkedInService;





class AuthenticationController extends BaseController
{
    /**
     * @param Request $request
     * @return mixed
     */
    public function login(Request $request)
    {
        try {
            // grab credentials from the request
            $credentials = $request->only('email', 'password');

            $this->validate($request, [
               'email'    => 'required|string',
               'password' => 'required|string|min:6'
            ]);

            // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
               throw new JWTException('invalid credentials', ErrorCodes::TOKEN_NOT_PROVIDED);
            }

            // all good so return the token
            return $this->success(['token' => $token], ['Authorization' => 'Bearer ' . $token]);


        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return $this->error('could not create token', ErrorCodes::TOKEN_CREATION_ERROR);
        } catch(ValidationException $e) {
            return $this->error('validation error', ErrorCodes::VALIDATION_ERROR);
        }


    }

    /**
     * Registration method (created request class @SailWithMe\Http\Requests\RegisterRequest)
     * @param RegisterRequest $request
     * @param UserService $service
     * @return mixed
     */
    public function register(RegisterRequest $request, UserService $service)
    {
        try {
            $data = $request->only(['email', 'password', 'gender', 'adult', 'alias']);

            //creating user
            $user = $service->create(
                $data['email'],
                $data['password'],
                $data['alias']
            );

            $user = $service->setUserData($user, ['gender' => $data['gender']]);
            $user = $service->setUserProperties($user, ['adult' => $data['adult']]);
            $token = $service->getAuthTokenFromUser($user);

            if (!$token) {
                throw new BaseException('could not get token', ErrorCodes::TOKEN_NOT_PROVIDED);
            }

            return $this->success(['token' => $token], ['Authorization' => 'Bearer ' . $token]);

        }catch (BaseException $e) {
            return $this->error($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    /**
     * Logout
     * @return mixed
     */
    public function logout()
    {
        try {
            $token = JWTAuth::getToken();
            JWTAuth::invalidate($token);

            if(Auth::logout()){
                return $this->success(['token' => ''], ['Authorization' => '']);
            }

            throw new BaseException('Error logout action', ErrorCodes::AUTHORIZED_CONTENT_ERROR);

        } catch (BaseException $e) {
            return $this->error($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    /**
     * @param Request $request
     * @param UserService $service
     * @return mixed
     */
    public function createReset(Request $request, UserService $service)
    {
        try {
            $email = $request->input('email');
            if(!$service->sendResetToken($email)){
                throw new BaseException('Error sending reset token', ErrorCodes::USER_PASSWORD_RESET_ERROR);
            }

            return $this->success([]);

        } catch (BaseException $e) {
            return $this->error($e->getMessage(), ErrorCodes::USER_PASSWORD_RESET_ERROR, $e->getErrors());
        }
    }

    /**
     * @param string $token
     * @param Request $request
     * @param UserService $service
     * @return mixed
     */
    public function reset(string $token, Request $request, UserService $service)
    {
        try {
            $password = $request->input('password');
            $this->validate($request, [
                'password' => 'required'
            ]);

            $authToken = $service->resetPassword($token, $password);

            return $this->success(['token' => $authToken], ['Authorization' => 'Bearer ' . $authToken]);

        } catch (ValidationException $e) {
            return $this->error(
                'Something wrong! Please check and try again!',
                ErrorCodes::USER_PASSWORD_RESET_ERROR
            );
        }
    }

    /**
     * @param Request $request
     * @param FacebookService $service
     * @return mixed
     */
    public function facebookLogin(Request $request, FacebookService $service)
    {
        try {
            $this->validate($request, ['access_token' => 'required|string']);


            $accessToken = $request->input('access_token');
            $authToken = $service->login($accessToken);

            return $this->success(['token' => $authToken], ['Authorization' => 'Bearer ' . $authToken]);

        } catch (ValidationException $exception) {
            return $this->error('Provide facebook access token to login!', ErrorCodes::TOKEN_NOT_PROVIDED);
        }
    }

    /**
     * Link for LinkedIn
     * @param Request $request
     * @param LinkedInService $service
     * @return mixed
     */
    public function linkedInLoginLink(Request $request, LinkedInService $service)
    {
        try {
            $referer = $request->headers->get('referer');

            if (!$this->isValidRefererDomain($referer)) {
                return redirect(config('app.url'));
            }

            $loginUrl = $service->getLoginUrl($referer);
            return redirect($loginUrl, 301);
        } catch (BaseException $e) {
             $this->errorLog($e->getMessage(), $e->getCode(), $e->getErrors());
             return $this->error('Failed to login in LinkedIn');
        }
    }

    /**
     * @param Request $request
     * @param LinkedInService $service
     * @return mixed
     */
    public function linkedInLogin(Request $request, LinkedInService $service)
    {
        try {
            $this->validate($request, [
                'state' => 'required|string',
                'code' => 'required|string',
            ]);


            $accessData = $service->getAccessTokenAndReturnLink($request->input('code'), $request->input('state'));
            if(!is_array($accessData)){
                throw new BaseException('Param access data not array', ErrorCodes::ENTITY_FORMAT_DEPRECATED);
            }

            return redirect($accessData['return_link'] . '?token=' . $accessData['token'],
                301, ['Authorization' => 'Bearer ' . $accessData['token']]);

        } catch(ValidationException $e){
            return $this->error('Callback url is not well formed!', ErrorCodes::UNKNOWN_ERROR);
        } catch (BaseException $e) {
            return $this->error($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    /**
     * @param string $token
     * @param UserService $service
     * @return mixed
     */
    public function confirm(string $token, UserService $service)
    {
        try {
            $user = $service->confirmUser($token);
            $token = $service->getAuthTokenFromUser($user);
            if(!$user) {
                throw new BaseException("User not confirmed", ErrorCodes::AUTHORIZED_CONTENT_ERROR);
            }
            if(!$token){
                throw new BaseException("Token not confirmed", ErrorCodes::AUTHORIZED_CONTENT_ERROR);
            }

            return redirect(secure_url('/') . '?token=' . $token);
        } catch (BaseException $e) {
            return $this->error($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    /**
     * @param $referer
     * @return bool
     */
    private function isValidRefererDomain($referer)
    {
        $domainUrl = config('app.url');

        if (!$referer || strpos($referer, 'http://localhost:3000/') === 0) {
            return true;
        }

        if (strpos($referer, $domainUrl) == 0) {
            $uri = str_replace($domainUrl, '', $referer);

            if ($uri[0] == '/') {
                return true;
            }
        }

        return false;
    }
}