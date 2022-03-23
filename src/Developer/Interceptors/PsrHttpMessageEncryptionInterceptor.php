<?php

namespace Mastercard\Developer\Interceptors;

use Mastercard\Developer\Encryption\FieldLevelEncryption;
use Mastercard\Developer\Encryption\FieldLevelEncryptionConfig;
use Mastercard\Developer\Encryption\FieldLevelEncryptionParams;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Utility class for encrypting RequestInterface and decrypting ResponseInterface payloads (see: https://www.php-fig.org/psr/psr-7/)
 * @package Mastercard\Developer\Interceptors
 */
class PsrHttpMessageEncryptionInterceptor extends PsrHttpMessageEncryptionAbstractInterceptor
{
    /**
     * @var FieldLevelEncryptionConfig
     */
    private $config;

    /**
     * PsrHttpMessageEncryptionInterceptor constructor.
     * @param FieldLevelEncryptionConfig $config A FieldLevelEncryptionConfig instance
     */
    public function __construct($config)
    {
        $this->config = $config;
    }


    public function encryptPayload(RequestInterface &$request, $requestPayload)
    {
        // Encrypt fields & update headers
        if ($this->config->useHttpHeaders()) {
            // Generate encryption params and add them as HTTP headers
            $params = FieldLevelEncryptionParams::generate($this->config);
            self::updateHeader($request, $this->config->getIvHeaderName(), $params->getIvValue());
            self::updateHeader($request, $this->config->getEncryptedKeyHeaderName(), $params->getEncryptedKeyValue());
            self::updateHeader($request, $this->config->getEncryptionCertificateFingerprintHeaderName(), $this->config->getEncryptionCertificateFingerprint());
            self::updateHeader($request, $this->config->getEncryptionKeyFingerprintHeaderName(), $this->config->getEncryptionKeyFingerprint());
            self::updateHeader($request, $this->config->getOaepPaddingDigestAlgorithmHeaderName(), $params->getOaepPaddingDigestAlgorithmValue());
            $encryptedPayload = FieldLevelEncryption::encryptPayload($requestPayload, $this->config, $params);
        } else {
            // Encryption params will be stored in the payload
            $encryptedPayload = FieldLevelEncryption::encryptPayload($requestPayload, $this->config);
        }

        return $encryptedPayload;
    }

    public function decryptPayload(ResponseInterface &$response, $responsePayload)
    {
        // Decrypt fields & update headers
        if ($this->config->useHttpHeaders()) {
            // Read encryption params from HTTP headers and delete headers
            $ivValue = self::readAndRemoveHeader($response, $this->config->getIvHeaderName());
            $encryptedKeyValue = self::readAndRemoveHeader($response, $this->config->getEncryptedKeyHeaderName());
            $oaepPaddingDigestAlgorithmValue = self::readAndRemoveHeader($response, $this->config->getOaepPaddingDigestAlgorithmHeaderName());
            self::readAndRemoveHeader($response, $this->config->getEncryptionCertificateFingerprintHeaderName());
            self::readAndRemoveHeader($response, $this->config->getEncryptionKeyFingerprintHeaderName());
            $params = new FieldLevelEncryptionParams($this->config, $ivValue, $encryptedKeyValue, $oaepPaddingDigestAlgorithmValue);
            $decryptedPayload = FieldLevelEncryption::decryptPayload($responsePayload, $this->config, $params);
        } else {
            // Encryption params are stored in the payload
            $decryptedPayload = FieldLevelEncryption::decryptPayload($responsePayload, $this->config);
        }

        return $decryptedPayload;
    }

    /**
     * @param MessageInterface $message
     * @param string           $name
     *
     * @return string|null
     */
    protected static function readAndRemoveHeader(&$message, $name)
    {
        if (empty($name)) {
            return null;
        }
        if (!$message->hasHeader($name)) {
            return null;
        }
        $values = $message->getHeader($name);
        $message = $message->withoutHeader($name);
        return $values[0];
    }
}
