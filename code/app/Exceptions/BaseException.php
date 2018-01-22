<?php

namespace SailWithMe\Exceptions;

use Exception;

class BaseException extends Exception
{
    private $errors = [];

    public function setErrors(string $key, array $data)
    {
        $this->errors[$key] = $data;
    }

    public function getErrors()
    {
        return $this->errors;
    }
}