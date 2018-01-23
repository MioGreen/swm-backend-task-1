<?php
namespace App\Http\Controllers\Traits;

use SailWithMe\Exceptions\BaseException;

trait BaseTrait
{
    /**
     * @param array $message
     * @param array $headers
     * @param int $code
     * @return mixed
     */
  public function success(array $message, array $headers = [], $code = 200)
  {
     if(!array_key_exists('success', $message)) {
       $message['success'] = true;
     }
     $response = response()->json($message, $code);
     if($headers) {
         $response->withHeaders($headers);
     }

     return $response;
  }


    /**
     * @param string $message
     * @param array $headers
     * @param int $code
     * @return mixed
     */
  public function error(string $message, $code = 500, $errors = null)
  {
      $response = response()->json(['error' => $message], $code);
      //write in log
      $this->errorLog($message, $code, $errors);

      return $response;
  }

    /**
     * @param string $erroMessage
     * @param int $errorCode
     */
  public function errorLog(string $erroMessage, int $errorCode, $errors = null): void
  {
    \Log::error("Message: " . $erroMessage . "- Code: ". $errorCode. " errors:" . $errors);
  }
}