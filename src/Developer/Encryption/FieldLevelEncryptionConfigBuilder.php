<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Json\JsonPath;
use Mastercard\Developer\Utils\EncodingUtils;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use phpseclib3\Crypt\Hash;

/**
 * A builder class for FieldLevelEncryptionConfig.
 * @see FieldLevelEncryptionConfig
 * @package Mastercard\Developer\Encryption
 */
class FieldLevelEncryptionConfigBuilder {

    private function __construct() {
        // This class can't be instantiated
    }

    private $encryptionCertificate;
    private $encryptionCertificateFingerprint;
    private $encryptionKeyFingerprint;
    private $decryptionKey;
    private $decryptionKeyPassword = false;
    private $encryptionPaths = array();
    private $decryptionPaths = array();
    private $oaepPaddingDigestAlgorithm;
    private $ivFieldName;
    private $ivHeaderName;
    private $oaepPaddingDigestAlgorithmFieldName;
    private $oaepPaddingDigestAlgorithmHeaderName;
    private $encryptedKeyFieldName;
    private $encryptedKeyHeaderName;
    private $encryptedValueFieldName;
    private $encryptionCertificateFingerprintFieldName;
    private $encryptionCertificateFingerprintHeaderName;
    private $encryptionKeyFingerprintFieldName;
    private $encryptionKeyFingerprintHeaderName;
    private $fieldValueEncoding;

    /**
     * Get an instance of the builder.
     * @return self
     */
    public static function aFieldLevelEncryptionConfig() {
        return new FieldLevelEncryptionConfigBuilder();
    }

    /**
     * @param OpenSSLCertificate|resource|string $encryptionCertificate
     * @see FieldLevelEncryptionConfig::encryptionCertificate.
     * @return $this
     */
    public function withEncryptionCertificate($encryptionCertificate) {
        $this->encryptionCertificate = $encryptionCertificate;
        return $this;
    }

    /**
     * @param string $encryptionCertificateFingerprint
     * @see FieldLevelEncryptionConfig::encryptionCertificateFingerprint.
     * @return $this
     */
    public function withEncryptionCertificateFingerprint($encryptionCertificateFingerprint) {
        $this->encryptionCertificateFingerprint = $encryptionCertificateFingerprint;
        return $this;
    }

    /**
     * @param string $encryptionKeyFingerprint
     * @see FieldLevelEncryptionConfig::encryptionKeyFingerprint.
     * @return $this
     */
    public function withEncryptionKeyFingerprint($encryptionKeyFingerprint) {
        $this->encryptionKeyFingerprint = $encryptionKeyFingerprint;
        return $this;
    }

    /**
     * @param OpenSSLAsymmetricKey|resource $decryptionKey
     * @see FieldLevelEncryptionConfig::decryptionKey.
     * @return $this
     */
    public function withDecryptionKey($decryptionKey, $password = false) {
        $this->decryptionKey = $decryptionKey;
        $this->decryptionKeyPassword = $password;
        return $this;
    }

    /**
     * @param string $jsonPathIn
     * @param string $jsonPathOut
     * @see FieldLevelEncryptionConfig::encryptionPaths.
     * @return $this
     */
    public function withEncryptionPath($jsonPathIn, $jsonPathOut) {
        $this->encryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * @param string $jsonPathIn
     * @param string $jsonPathOut
     * @see FieldLevelEncryptionConfig::decryptionPaths.
     * @return $this
     */
    public function withDecryptionPath($jsonPathIn, $jsonPathOut) {
        $this->decryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * @param string $oaepPaddingDigestAlgorithm
     * @see FieldLevelEncryptionConfig::oaepPaddingDigestAlgorithm.
     * @return $this
     */
    public function withOaepPaddingDigestAlgorithm($oaepPaddingDigestAlgorithm) {
        $this->oaepPaddingDigestAlgorithm = $oaepPaddingDigestAlgorithm;
        return $this;
    }

    /**
     * @param string|null $ivFieldName
     * @see FieldLevelEncryptionConfig::ivFieldName.
     * @return $this
     */
    public function withIvFieldName($ivFieldName) {
        $this->ivFieldName = $ivFieldName;
        return $this;
    }

    /**
     * @param string|null $oaepPaddingDigestAlgorithmFieldName
     * @see FieldLevelEncryptionConfig::oaepPaddingDigestAlgorithmFieldName.
     * @return $this
     */
    public function withOaepPaddingDigestAlgorithmFieldName($oaepPaddingDigestAlgorithmFieldName) {
        $this->oaepPaddingDigestAlgorithmFieldName = $oaepPaddingDigestAlgorithmFieldName;
        return $this;
    }

    /**
     * @param string|null $encryptedKeyFieldName
     * @see FieldLevelEncryptionConfig::encryptedKeyFieldName.
     * @return $this
     */
    public function withEncryptedKeyFieldName($encryptedKeyFieldName) {
        $this->encryptedKeyFieldName = $encryptedKeyFieldName;
        return $this;
    }

    /**
     * @param string $encryptedValueFieldName
     * @see FieldLevelEncryptionConfig::encryptedValueFieldName.
     * @return $this
     */
    public function withEncryptedValueFieldName($encryptedValueFieldName) {
        $this->encryptedValueFieldName = $encryptedValueFieldName;
        return $this;
    }

    /**
     * @param string|null $encryptionCertificateFingerprintFieldName
     * @see FieldLevelEncryptionConfig::encryptionCertificateFingerprintFieldName.
     * @return $this
     */
    public function withEncryptionCertificateFingerprintFieldName($encryptionCertificateFingerprintFieldName) {
        $this->encryptionCertificateFingerprintFieldName = $encryptionCertificateFingerprintFieldName;
        return $this;
    }

    /**
     * @param string|null $encryptionKeyFingerprintFieldName
     * @see FieldLevelEncryptionConfig::encryptionKeyFingerprintFieldName.
     * @return $this
     */
    public function withEncryptionKeyFingerprintFieldName($encryptionKeyFingerprintFieldName) {
        $this->encryptionKeyFingerprintFieldName = $encryptionKeyFingerprintFieldName;
        return $this;
    }

    /**
     * @param int $fieldValueEncoding
     * @see FieldLevelEncryptionConfig::fieldValueEncoding.
     * @return $this
     */
    public function withFieldValueEncoding($fieldValueEncoding) {
        $this->fieldValueEncoding = $fieldValueEncoding;
        return $this;
    }

    /**
     * @param string $ivHeaderName
     * @see FieldLevelEncryptionConfig::ivHeaderName.
     * @return $this
     */
    public function withIvHeaderName($ivHeaderName) {
        $this->ivHeaderName = $ivHeaderName;
        return $this;
    }

    /**
     * @param string $oaepPaddingDigestAlgorithmHeaderName
     * @see FieldLevelEncryptionConfig::oaepPaddingDigestAlgorithmHeaderName.
     * @return $this
     */
    public function withOaepPaddingDigestAlgorithmHeaderName($oaepPaddingDigestAlgorithmHeaderName) {
        $this->oaepPaddingDigestAlgorithmHeaderName = $oaepPaddingDigestAlgorithmHeaderName;
        return $this;
    }

    /**
     * @param string $encryptedKeyHeaderName
     * @see FieldLevelEncryptionConfig::encryptedKeyHeaderName.
     * @return $this
     */
    public function withEncryptedKeyHeaderName($encryptedKeyHeaderName) {
        $this->encryptedKeyHeaderName = $encryptedKeyHeaderName;
        return $this;
    }

    /**
     * @param string $encryptionCertificateFingerprintHeaderName
     * @see FieldLevelEncryptionConfig::encryptionCertificateFingerprintHeaderName.
     * @return $this
     */
    public function withEncryptionCertificateFingerprintHeaderName($encryptionCertificateFingerprintHeaderName) {
        $this->encryptionCertificateFingerprintHeaderName = $encryptionCertificateFingerprintHeaderName;
        return $this;
    }

    /**
     * @param string $encryptionKeyFingerprintHeaderName
     * @see FieldLevelEncryptionConfig::encryptionKeyFingerprintHeaderName.
     * @return $this
     */
    public function withEncryptionKeyFingerprintHeaderName($encryptionKeyFingerprintHeaderName) {
        $this->encryptionKeyFingerprintHeaderName = $encryptionKeyFingerprintHeaderName;
        return $this;
    }

    /**
     * Build a FieldLevelEncryptionConfig.
     * @see FieldLevelEncryptionConfig
     * @throws EncryptionException
     * @throws \InvalidArgumentException
     * @return FieldLevelEncryptionConfig
     */
    public function build() {

        $this->checkJsonPathParameterValues();
        $this->checkParameterValues();
        $this->checkParameterConsistency();

        $this->computeEncryptionCertificateFingerprintWhenNeeded();
        $this->computeEncryptionKeyFingerprintWhenNeeded();

        return new FieldLevelEncryptionConfig(
            $this->encryptionCertificate,
            $this->encryptionCertificateFingerprint,
            $this->encryptionKeyFingerprint,
            $this->decryptionKey,
            $this->decryptionKeyPassword,
            $this->encryptionPaths,
            $this->decryptionPaths,
            $this->oaepPaddingDigestAlgorithm,
            $this->oaepPaddingDigestAlgorithmFieldName,
            $this->oaepPaddingDigestAlgorithmHeaderName,
            $this->ivFieldName,
            $this->ivHeaderName,
            $this->encryptedKeyFieldName,
            $this->encryptedKeyHeaderName,
            $this->encryptedValueFieldName,
            $this->encryptionCertificateFingerprintFieldName,
            $this->encryptionCertificateFingerprintHeaderName,
            $this->encryptionKeyFingerprintFieldName,
            $this->encryptionKeyFingerprintHeaderName,
            $this->fieldValueEncoding
        );
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkJsonPathParameterValues() {
        foreach ($this->decryptionPaths as $jsonPathIn => $jsonPathOut) {
            if (!JsonPath::isPathDefinite($jsonPathIn) || !JsonPath::isPathDefinite($jsonPathOut)) {
                throw new \InvalidArgumentException('JSON paths for decryption must point to a single item!');
            }
        }
        foreach ($this->encryptionPaths as $jsonPathIn => $jsonPathOut) {
            if (!JsonPath::isPathDefinite($jsonPathIn) || !JsonPath::isPathDefinite($jsonPathOut)) {
                throw new \InvalidArgumentException('JSON paths for encryption must point to a single item!');
            }
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkParameterValues() {
        if (empty($this->oaepPaddingDigestAlgorithm)) {
            throw new \InvalidArgumentException('The digest algorithm for OAEP cannot be empty!');
        }

        if ('SHA-256' !== $this->oaepPaddingDigestAlgorithm && 'SHA-512' !== $this->oaepPaddingDigestAlgorithm) {
            throw new \InvalidArgumentException('Unsupported OAEP digest algorithm: ' . $this->oaepPaddingDigestAlgorithm . '!');
        }

        if (empty($this->fieldValueEncoding)) {
            throw new \InvalidArgumentException('Value encoding for fields and headers cannot be empty!');
        }

        if (empty($this->ivFieldName) && empty($this->ivHeaderName)) {
            throw new \InvalidArgumentException('At least one of IV field name or IV header name must be set!');
        }

        if (empty($this->encryptedKeyFieldName) && empty($this->encryptedKeyHeaderName)) {
            throw new \InvalidArgumentException('At least one of encrypted key field name or encrypted key header name must be set!');
        }

        if (empty($this->encryptedValueFieldName)) {
            throw new \InvalidArgumentException('Encrypted value field name cannot be empty!');
        }
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkParameterConsistency () {
        if (!empty($this->decryptionPaths) && empty($this->decryptionKey)) {
            throw new \InvalidArgumentException('Can\'t decrypt without decryption key!');
        }

        if (!empty($this->encryptionPaths) && empty($this->encryptionCertificate)) {
            throw new \InvalidArgumentException('Can\'t encrypt without encryption key!');
        }

        if (!empty($this->ivHeaderName) && empty($this->encryptedKeyHeaderName)
            || empty($this->ivHeaderName) && !empty($this->encryptedKeyHeaderName)) {
            throw new \InvalidArgumentException('IV header name and encrypted key header name must be both set or both unset!');
        }

        if (!empty($this->ivFieldName) && empty($this->encryptedKeyFieldName)
            || empty($this->ivFieldName) && !empty($this->encryptedKeyFieldName)) {
            throw new \InvalidArgumentException('IV field name and encrypted key field name must be both set or both unset!');
        }
    }

    /**
     * @throws EncryptionException
     */
    private function computeEncryptionCertificateFingerprintWhenNeeded() {
        $providedEncryptionCertificate = $this->encryptionCertificate;
        if (empty($providedEncryptionCertificate) || !empty($this->encryptionCertificateFingerprint)) {
            // No encryption certificate set or certificate fingerprint already provided
            return;
        }
        try {
            $this->encryptionCertificateFingerprint = openssl_x509_fingerprint($providedEncryptionCertificate, 'sha256');
        } catch (\Exception $e) {
            throw new EncryptionException('Failed to compute encryption certificate fingerprint!', $e);
        }
    }

    /**
     * @throws EncryptionException
     */
    private function computeEncryptionKeyFingerprintWhenNeeded() {
        $providedEncryptionCertificate = $this->encryptionCertificate;
        if (empty($providedEncryptionCertificate) || !empty($this->encryptionKeyFingerprint)) {
            // No encryption certificate set or key fingerprint already provided
            return;
        }
        try {
            $publicKeyPem = openssl_pkey_get_details(openssl_pkey_get_public($providedEncryptionCertificate))['key'];
            $publicKeyDer = EncodingUtils::pemToDer($publicKeyPem, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----');
            $hash = new Hash('sha256');
            $this->encryptionKeyFingerprint = EncodingUtils::encodeBytes($hash->hash($publicKeyDer), FieldValueEncoding::HEX);
        } catch (\Exception $e) {
            throw new EncryptionException('Failed to compute encryption key fingerprint!', $e);
        }
    }
}
