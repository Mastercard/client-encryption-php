<?php

namespace Mastercard\Developer\Encryption;
use Error;
use Exception;
use Mastercard\Developer\Encryption\RSA\RSA;
use Mastercard\Developer\Utils\EncodingUtils;

/**
 * Encryption parameters for computing field level encryption/decryption.
 * @package Mastercard\Developer\Encryption
 */
class FieldLevelEncryptionParams {

    const SYMMETRIC_CYPHER = 'AES-128-CBC';
    const SYMMETRIC_KEY_SIZE = 128;

    private $ivValue;
    private $encryptedKeyValue;
    private $oaepPaddingDigestAlgorithmValue;
    private $config;
    private $secretKey;
    private $iv;

    /**
     * @param FieldLevelEncryptionConfig $config
     * @param string|null $ivValue
     * @param string|null $encryptedKeyValue
     * @param string|null $oaepPaddingDigestAlgorithmValue
     */
    public function __construct($config, $ivValue, $encryptedKeyValue, $oaepPaddingDigestAlgorithmValue = null) {
        $this->ivValue = $ivValue;
        $this->encryptedKeyValue = $encryptedKeyValue;
        $this->oaepPaddingDigestAlgorithmValue = $oaepPaddingDigestAlgorithmValue;
        $this->config = $config;
    }

    /**
     * Generate encryption parameters.
     * @param FieldLevelEncryptionConfig $config A FieldLevelEncryptionConfig instance
     * @return FieldLevelEncryptionParams
     * @throws EncryptionException
     */
    public static function generate($config) {

        // Generate a random IV
        $ivLength = openssl_cipher_iv_length(self::SYMMETRIC_CYPHER);
        $iv = openssl_random_pseudo_bytes($ivLength);
        $ivValue = EncodingUtils::encodeBytes($iv, $config->getFieldValueEncoding());

        // Generate an AES secret key
        $secretKey = openssl_random_pseudo_bytes(self::SYMMETRIC_KEY_SIZE / 8);

        // Encrypt the secret key
        // $encryptedSecretKeyBytes = self::wrapSecretKey($config, $secretKey);
        $encryptedSecretKeyBytes = RSA::wrapSecretKey($config->getEncryptionCertificate(), $secretKey);
        $encryptedKeyValue = EncodingUtils::encodeBytes($encryptedSecretKeyBytes, $config->getFieldValueEncoding());

        // Compute the OAEP padding digest algorithm
        $oaepPaddingDigestAlgorithmValue = str_replace('-', '', $config->getOaepPaddingDigestAlgorithm());

        $params = new FieldLevelEncryptionParams($config, $ivValue, $encryptedKeyValue, $oaepPaddingDigestAlgorithmValue);
        $params->secretKey = $secretKey;
        $params->iv = $iv;
        return $params;
    }

    /**
     * @return string|null
     */
    public function getIvValue() {
        return $this->ivValue;
    }

    /**
     * @return string|null
     */
    public function getEncryptedKeyValue() {
        return $this->encryptedKeyValue;
    }

    /**
     * @return string|null
     */
    public function getOaepPaddingDigestAlgorithmValue() {
        return $this->oaepPaddingDigestAlgorithmValue;
    }

    /**
     * @return string|false
     * @throws EncryptionException
     */
    public function getIvBytes() {
        try {
            if (!empty($this->iv)) {
                return $this->iv;
            }
            // Decode the IV
            $this->iv = EncodingUtils::decodeValue($this->ivValue, $this->config->getFieldValueEncoding());
            return $this->iv;
        } catch (Exception $e) {
            throw new EncryptionException('Failed to decode the provided IV value!', $e);
        }
    }

    /**
     * @return string
     * @throws EncryptionException
     */
    public function getSecretKeyBytes() {
        try {
            if (!empty($this->secretKey)) {
                return $this->secretKey;
            }
            // Decrypt the AES secret key
            $encryptedSecretKeyBytes = EncodingUtils::decodeValue($this->encryptedKeyValue, $this->config->getFieldValueEncoding());
            $this->secretKey = RSA::unwrapSecretKey($this->config->getDecryptionKey(), $encryptedSecretKeyBytes, $this->oaepPaddingDigestAlgorithmValue);
            return $this->secretKey;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new EncryptionException('Failed to decode and unwrap the provided secret key value!', $e);
        }
    }

}
