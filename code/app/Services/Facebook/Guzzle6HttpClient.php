<?php

namespace SailWithMe\Services\Facebook;

use Facebook\Exceptions\FacebookSDKException;
use Facebook\Http\GraphRawResponse;
use Facebook\HttpClients\FacebookHttpClientInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;

class Guzzle6HttpClient implements FacebookHttpClientInterface
{
    private $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function send($url, $method, $body, array $headers, $timeOut)
    {
        $request = new Request($method, $url, $headers, $body);

        try {
            $response = $this->client->send($request, ['timeout' => $timeOut, 'http_errors' => false]);
        } catch (RequestException $e) {
            throw new FacebookSDKException($e->getMessage(), $e->getCode());
        }

        $httpStatusCode = $response->getStatusCode();
        $responseHeaders = $response->getHeaders();

        foreach ($responseHeaders as $key => $values) {
            $responseHeaders[$key] = implode(', ', $values);
        }

        $responseBody = $response->getBody()->getContents();

        return new GraphRawResponse(
            $responseHeaders,
            $responseBody,
            $httpStatusCode);
    }
}