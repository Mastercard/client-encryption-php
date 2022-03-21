<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Json\JsonPath;

abstract class EncryptionConfigBuilder
{
    /**
     * @var string
     */
    protected $encryptionCertificate;

    /**
     * @var string|null
     */
    protected $encryptionKeyFingerprint = null;

    /**
     * @var string|null
     */
    protected $decryptionKey = null;

    /**
     * @var array
     */
    protected $encryptionPaths = [];

    /**
     * @var array
     */
    protected $decryptionPaths = [];

    /**
     * @var string|null
     */
    protected $encryptedValueFieldName = null;

    protected function computeEncryptionKeyFingerprintWhenNeeded()
    {
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

    protected function checkJsonPathParameterValues()
    {
        foreach ($this->decryptionPaths as $key => $value) {
            if (!JsonPath::isPathDefinite($key) || !JsonPath::isPathDefinite($value)) {
                throw new \InvalidArgumentException("JSON paths for decryption must point to a single item!");
            }
        }

        foreach ($this->encryptionPaths as $key => $value) {
            if (!JsonPath::isPathDefinite($key) || !JsonPath::isPathDefinite($value)) {
                throw new \InvalidArgumentException("JSON paths for decryption must point to a single item!");
            }
        }
    }
}
