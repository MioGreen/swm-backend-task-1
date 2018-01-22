<?php

namespace SailWithMe\Services\Facebook;

use Facebook\Facebook;
use GuzzleHttp\Client;

/**
 * Class FacebookClient
 * @package SailWithMe\Services\Facebook
 */
class FacebookClient
{
    private $fbClient;

    public function __construct(Client $client)
    {
        $this->fbClient = new Facebook([
            'app_id' => config('facebook.app-id'),
            'secret' => config('facebook.secret'),
            'default_graph_version' => config('facebook.version'),
            'http_client_handler' => new Guzzle6HttpClient($client)
        ]);
    }

    public function __call($name, $arguments)
    {
        return call_user_func_array([$this->fbClient, $name], $arguments);
    }
}