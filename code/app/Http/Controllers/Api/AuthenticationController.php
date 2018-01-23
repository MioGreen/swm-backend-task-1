<?php

namespace SailWithMe\Http\Controllers\Api;

use Auth;
use Illuminate\Http\Request;
use JWTAuth;
use Redirect;
use SailWithMe\Constants\ErrorCodes;
use SailWithMe\Exceptions\BaseException;
use SailWithMe\Services\Facebook\FacebookService;
use SailWithMe\Services\LinkedIn\LinkedInService;
use SailWithMe\Services\UserService;
use Tymon\JWTAuth\Exceptions\JWTException;
use Validator;

class AuthenticationController extends BaseController
{
    public function login(Request $request)
    {
        // grab credentials from the request
        $credentials = $request->only('email', 'password');

        try {
            // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                throw new JWTException('invalid credentials', ErrorCodes::TOKEN_NOT_PROVIDED);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            $this->logError('could not create token', ErrorCodes::TOKEN_CREATION_ERROR);

            return response()->json(['success' => false, 'error' => 'Failed to login, please try again.'], 500);

        }

        // all good so return the token
        return response()->json(['token' => $token], ['Authorization' => 'Bearer ' . $token]);
    }

    public function register(Request $request, UserService $service)
    {
        try {
            //getting post data
            $validator = Validator::make($request->all(), [
                'is_adult' => 'required|accepted',
                'policy_acception' => 'required|accepted',
            ]);

            if ($validator->fails()) {
                throw new BaseException("You must be at least 18 years old and accept projects policy!");
            }

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

            return response()->json(['token' => $token], ['Authorization' => 'Bearer ' . $token]);
        } catch (BaseException $e) {
            $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to register, please try again.'], 401);

        }
    }

    public function logout()
    {
        try {
            $token = JWTAuth::getToken();
            JWTAuth::invalidate($token);


            if(!Auth::logout()){
                throw new BaseException("Аn error occurred during the logout action", ErrorCodes::AUTHORIZED_CONTENT_ERROR);
            }

            return response()->json(['token' => ''], ['Authorization' => '']);
        } catch (BaseException $e) {

            $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to logout, please try again.'], 500);

        }
    }

    public function createReset(Request $request, UserService $service)
    {
        try {
            $email = $request->input('email');

            if($service->sendResetToken($email)){
                throw new BaseException('Аn error occurred while sending the reset token');
            }
            return response()->json([]);
        } catch (BaseException $exception) {
            $this->logError($exception->getMessage(), ErrorCodes::USER_PASSWORD_RESET_ERROR,
                $exception->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to create reset, please try again.'], 500);

        }
    }

    public function reset(string $token, Request $request, UserService $service)
    {
        try {
            $fields = $request->only('password');

            $validator = Validator::make($fields, ['password' => 'required']);

            if ($validator->fails()) {
                throw new BaseException(
                    'Something wrong! Please check and try again!',
                    ErrorCodes::AUTHORIZED_CONTENT_ERROR,
                    ['validationErrors' => $validator->errors()]);
            }

            $authToken = $service->resetPassword($token, $fields['password']);

            return response()->json(['token' => $authToken], ['Authorization' => 'Bearer ' . $authToken]);
        } catch (BaseException $exception) {
             $this->logError($exception->getMessage(), ErrorCodes::USER_PASSWORD_RESET_ERROR,
                $exception->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to reset, please try again.'], 500);

        }
    }

    public function facebookLogin(Request $request, FacebookService $service)
    {
        try {
            $validator = Validator::make($request->all(), ['access_token' => 'required|string']);

            if ($validator->fails()) {
                throw new BaseException('Provide facebook access token to login!', ErrorCodes::TOKEN_NOT_PROVIDED);
            }

            $accessToken = $request->input('access_token');
            $authToken = $service->login($accessToken);

            return response()->json(['token' => $authToken], ['Authorization' => 'Bearer ' . $authToken]);
        } catch (BaseException $exception) {
             $this->logError($exception->getMessage(), $exception->getCode(), $exception->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to facebook login, please try again.'], 500);
        }
    }

    public function linkedInLoginLink(Request $request, LinkedInService $service)
    {
        try {
            $referer = $request->headers->get('referer');

            if (!$this->isValidRefererDomain($referer)) {
                return Redirect::to(config('app.url'));
            }

            $loginUrl = $service->getLoginUrl($referer);
            return Redirect::to($loginUrl, 301);
        } catch (BaseException $e) {
            $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to login, please try again.'], 500);

        }
    }

    public function linkedInLogin(Request $request, LinkedInService $service)
    {
        try {
            $validator = Validator::make($request->all(), [
                'state' => 'required|string',
                'code' => 'required|string',
            ]);

            if ($validator->fails()) {
                throw new BaseException('Callback url is not well formed!', ErrorCodes::UNKNOWN_ERROR);
            }

            $accessData = $service->getAccessTokenAndReturnLink($request->input('code'), $request->input('state'));

            return Redirect::to($accessData['return_link'] . '?token=' . $accessData['token'],
                301, ['Authorization' => 'Bearer ' . $accessData['token']]);
        } catch (BaseException $e) {
            $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to linkedin login, please try again.'], 500);
        }
    }

    public function confirm(string $token, UserService $service)
    {
        try {
            $user = $service->confirmUser($token);
            $token = $service->getAuthTokenFromUser($user);

            if($user && $token){
                throw new BaseException('AUser auth token error', ErrorCodes::AUTHORIZED_CONTENT_ERROR);

            }
            return Redirect::to(secure_url('/') . '?token=' . $token);
        } catch (BaseException $e) {
            $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());

            return response()->json(['success' => false, 'error' => 'Failed to confirm, please try again.'], 500);
        }
    }

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

    private function logError($errorMessage, $errorCode, $errors = null){

        \Log::error('AuthenticationController error::'. $errorMessage . 'code::'. $errorCode . 'additional info::' . $errors);

    }

}