<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Json\JsonPath;

abstract class EncryptionConfigBuilder
{
    protected $encryptionCertificate;
    protected string|null $encryptionKeyFingerprint = null;
    protected string|null $decryptionKey = null;
    // FieldLevelEncryptionConfig.FieldValueEncoding fieldValueEncoding;
    protected array $encryptionPaths = [];
    protected array $decryptionPaths = [];
    protected string|null $encryptedValueFieldName = null;


    protected function computeEncryptionKeyFingerprintWhenNeeded() {
        try {
            if ($this->encryptionCertificate == null || isset($this->encryptionKeyFingerprint)) {
                // No encryption certificate set or key fingerprint already provided
                return;
            }

            $cert = openssl_x509_read($this->encryptionCertificate);
            $this->encryptionKeyFingerprint = openssl_x509_fingerprint($cert, 'sha256');
        } catch (\Exception $e) {
            throw new EncryptionException("Failed to compute encryption key fingerprint!", $e);
        }
    }

    protected function checkJsonPathParameterValues() {
        foreach($this->decryptionPaths as $key=>$value) {
            if (!JsonPath::isPathDefinite($key) || !JsonPath::isPathDefinite($value)){
                throw new \InvalidArgumentException("JSON paths for decryption must point to a single item!");
            }
        }

        foreach($this->encryptionPaths as $key=>$value) {
            if (!JsonPath::isPathDefinite($key) || !JsonPath::isPathDefinite($value)){
                throw new \InvalidArgumentException("JSON paths for decryption must point to a single item!");
            }
        }
    }
}
