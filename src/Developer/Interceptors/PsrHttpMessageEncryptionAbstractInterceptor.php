<?php

namespace Mastercard\Developer\Interceptors;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use Mastercard\Developer\Encryption\EncryptionException;

/**
 * Utility class for encrypting RequestInterface and decrypting ResponseInterface payloads (see: https://www.php-fig.org/psr/psr-7/)
 * @package Mastercard\Developer\Interceptors
 */
abstract class PsrHttpMessageEncryptionAbstractInterceptor
{
    abstract public function encryptPayload(RequestInterface &$request, $requestPayload);
    abstract public function decryptPayload(ResponseInterface &$response, $responsePayload);

    /**
     * Encrypt payloads from RequestInterface objects when needed.
     * @param RequestInterface $request A RequestInterface object
     * @return RequestInterface The updated RequestInterface object
     * @throws EncryptionException
     */
    public function interceptRequest(RequestInterface &$request)
    {
        try {
            $body = $request->getBody();
            $payload = $body->__toString();
            if (empty($payload)) {
                // Nothing to encrypt
                return $request;
            }

            $encryptedPayload = $this->encryptPayload($request, $payload);

            // Update body and content length
            $updatedBody = new PsrStreamInterfaceImpl();
            $updatedBody->write($encryptedPayload);
            $request = $request->withBody($updatedBody);
            self::updateHeader($request, 'Content-Length', $updatedBody->getSize());
            return $request;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new EncryptionException('Failed to intercept and encrypt request!', $e);
        }
    }

    /**
     * Decrypt payloads from ResponseInterface objects when needed.
     * @param ResponseInterface $response A ResponseInterface object
     * @return ResponseInterface The updated ResponseInterface object
     * @throws EncryptionException
     */
    public function interceptResponse(ResponseInterface &$response)
    {
        try {
            $body = $response->getBody();
            $payload = $body->__toString();
            if (empty($payload)) {
                // Nothing to decrypt
                return $response;
            }

            $decryptedPayload = $this->decryptPayload($response, $payload);

            // Update body and content length
            $updatedBody = new PsrStreamInterfaceImpl();
            $updatedBody->write($decryptedPayload);
            $response = $response->withBody($updatedBody);
            self::updateHeader($response, 'Content-Length', $updatedBody->getSize());
            return $response;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new EncryptionException('Failed to intercept and encrypt request!', $e);
        }
    }

    /**
     * @param MessageInterface $message
     * @param string           $name
     * @param string           $value
     */
    protected static function updateHeader(&$message, $name, $value)
    {
        if (empty($name)) {
            // Do nothing
            return $message;
        }
        $message = $message->withHeader($name, $value);
    }
}
