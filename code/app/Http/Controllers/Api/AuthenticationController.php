<?php

namespace SailWithMe\Http\Controllers\Api;

use Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
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
        try {
        	// grab credentials from the request
	        $credentials = $request->only('email', 'password');

	        // attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                return $this->logError('invalid credentials', ErrorCodes::TOKEN_NOT_PROVIDED);
            }
        } catch (JWTException $e) {
            // something went wrong whilst attempting to encode the token
            return $this->logError('could not create token', ErrorCodes::TOKEN_CREATION_ERROR);
        }

        // all good so return the token
        return $this->sendToken($token);
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

            return $this->sendToken($token);
        } catch (BaseException $e) {
            return $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    public function logout()
    {
        try {
            $token = JWTAuth::getToken();
            JWTAuth::invalidate($token);
            Auth::logout();

            return $this->sendToken();
        } catch (BaseException $e) {
            return $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    public function createReset(Request $request, UserService $service)
    {
        try {
            $email = $request->input('email');
            $service->sendResetToken($email);

            return $this->sendToken();
        } catch (BaseException $exception) {
            return $this->logError($exception->getMessage(), ErrorCodes::USER_PASSWORD_RESET_ERROR,
                $exception->getErrors());
        }
    }

    public function reset(string $token, Request $request, UserService $service)
    {
        try {
            $fields = $request->only('password');

            $validator = Validator::make($fields, ['password' => 'required']);

            if ($validator->fails()) {
                return $this->logError(
                    'Something wrong! Please check and try again!',
                    ErrorCodes::USER_PASSWORD_RESET_ERROR,
                    ['validationErrors' => $validator->errors()]);
            }

            $authToken = $service->resetPassword($token, $fields['password']);

            return $this->sendToken($authToken);
        } catch (BaseException $exception) {
            return $this->logError($exception->getMessage(), ErrorCodes::USER_PASSWORD_RESET_ERROR,
                $exception->getErrors());
        }
    }

    public function facebookLogin(Request $request, FacebookService $service)
    {
        try {
            $validator = Validator::make($request->all(), ['access_token' => 'required|string']);

            if ($validator->fails()) {
                return $this->logError('Provide facebook access token to login!', ErrorCodes::TOKEN_NOT_PROVIDED);
            }

            $accessToken = $request->input('access_token');
            $authToken = $service->login($accessToken);

            return $this->sendToken($authToken);
        } catch (BaseException $exception) {
            return $this->logError($exception->getMessage(), $exception->getCode(), $exception->getErrors());
        }
    }

    public function linkedInLoginLink(Request $request, LinkedInService $service)
    {
        try {
            $referrer = $request->headers->get('referrer');

            if (!$this->isValidRefererDomain($referrer)) {
                return redirect(config('app.url'));
            }

            $loginUrl = $service->getLoginUrl($referrer);
            return redirect($loginUrl, 301);
        } catch (BaseException $e) {
            return $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());
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
                return $this->logError('Callback url is not well formed!', ErrorCodes::UNKNOWN_ERROR);
            }

            $accessData = $service->getAccessTokenAndReturnLink($request->input('code'), $request->input('state'));

            return redirect($accessData['return_link'] . '?token=' . $accessData['token'],
                301, ['Authorization' => 'Bearer ' . $accessData['token']]);
        } catch (BaseException $e) {
            return $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    public function confirm(string $token, UserService $service)
    {
        try {
            $user = $service->confirmUser($token);
            $token = $service->getAuthTokenFromUser($user);

            return redirect(secure_url('/') . '?token=' . $token);
        } catch (BaseException $e) {
            return $this->logError($e->getMessage(), $e->getCode(), $e->getErrors());
        }
    }

    private function isValidRefererDomain($referrer)
    {
        $domainUrl = config('app.url');

        if ( !$referrer || strpos($referrer, 'http://localhost:3000/') === 0) {
            return true;
        }

        if ( strpos($referrer, $domainUrl) == 0) {
            $uri = str_replace($domainUrl, '', $referrer);

            if ($uri[0] == '/') {
                return true;
            }
        }

        return false;
    }
	
	protected function logError($message, $errorCode, $errors = []) {
		Log::info(
			$message,
			array_merge([ 'code' => $errorCode ], $errors)
		);

		return $this->error($message, $errorCode, $errors);
	}

	protected function sendToken($token = '') {
		return $this->success(['token' => $token], ['Authorization' => 'Bearer ' . $token]);
	}
}