<?php

namespace Mastercard\Developer\Interceptors;

use Mastercard\Developer\Encryption\JweConfig;
use Mastercard\Developer\Encryption\JweEncryption;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Utility class for encrypting RequestInterface and decrypting ResponseInterface payloads (see: https://www.php-fig.org/psr/psr-7/)
 * @package Mastercard\Developer\Interceptors
 */
class PsrHttpMessageJweInterceptor extends PsrHttpMessageEncryptionInterceptor
{
    /**
     * @var JweConfig
     */
    private $config;

    /**
     * PsrHttpMessageFieldLevelEncryptionInterceptor constructor.
     * @param JweConfig $config A JweConfig instance
     */
    public function __construct($config)
    {
        $this->config = $config;
    }

    public function encryptPayload(RequestInterface &$request, $requestPayload)
    {
        return JweEncryption::encryptPayload($requestPayload, $this->config);
    }

    public function decryptPayload(ResponseInterface &$response, $responsePayload)
    {
        return JweEncryption::decryptPayload($responsePayload, $this->config);
    }
}
