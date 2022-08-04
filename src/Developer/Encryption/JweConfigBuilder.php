<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Utils\EncodingUtils;
use phpseclib3\Crypt\Hash;

class JweConfigBuilder extends EncryptionConfigBuilder {

    /**
     * @return JweConfigBuilder 
     * Get an instance of the builder.
     */
    public static function aJweEncryptionConfig() {
        return new JweConfigBuilder();
    }

    /**
     * @return JweConfig 
     * Build a {@link JweConfig}.
     *
     * @throws EncryptionException
     */
    public function build() {
        $this->checkParameterValues();
        $this->computeEncryptionKeyFingerprint($this->encryptionCertificate);
        $this->checkJsonPathParameterValues();
        $config = new JweConfig();
        $config->setEncryptionCertificate($this->encryptionCertificate);
        $config->setEncryptionKeyFingerprint($this->encryptionKeyFingerprint);
        $config->setDecryptionKey($this->decryptionKey);
        $config->setEncryptionPaths(empty($this->encryptionPaths) ? ["$" => "$"] : $this->encryptionPaths);
        $config->setDecryptionPaths(empty($this->decryptionPaths) ? ["$.encryptedData" => "$"] : $this->decryptionPaths);
        $config->setEncryptedValueFieldName($this->encryptedValueFieldName == null ? "encryptedData" : $this->encryptedValueFieldName);
        return $config;
    }

    /**
     * @param string $encryptionCertificate
     * @return JweConfigBuilder 
     * See: {@link EncryptionConfig#encryptionCertificate}.
     */
    public function withEncryptionCertificate($encryptionCertificate) {
        $this->encryptionCertificate = $encryptionCertificate;
        return $this;
    }

    /**
     * @param string $decryptionKey
     * @return JweConfigBuilder 
     * See: {@link EncryptionConfig#decryptionKey}.
     */
    public function withDecryptionKey($decryptionKey) {
        $this->decryptionKey = $decryptionKey;
        return $this;
    }
    
    /**
     * @param string $jsonPathIn
     * @param string $jsonPathOut
     * @return JweConfigBuilder 
     * See: {@link EncryptionConfig#encryptionPaths}.
     */
    public function withEncryptionPath($jsonPathIn, $jsonPathOut) {
        $this->encryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * @param string $jsonPathIn
     * @param string $jsonPathOut
     * @return JweConfigBuilder 
     * See: {@link EncryptionConfig#decryptionPaths}.
     */
    public function withDecryptionPath($jsonPathIn, $jsonPathOut) {
        $this->decryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * @param string $encryptedValueFieldName
     * @return JweConfigBuilder 
     * See: {@link EncryptionConfig#encryptedValueFieldName}.
     */
    public function withEncryptedValueFieldName($encryptedValueFieldName) {
        $this->encryptedValueFieldName = $encryptedValueFieldName;
        return $this;
    }

    private function checkParameterValues() {
        if ($this->decryptionKey == null && $this->encryptionCertificate == null) {
            throw new \InvalidArgumentException("You must include at least an encryption certificate or a decryption key");
        }
    }

    /**
     * @param mixed $encryptionCertificate
     * @throws EncryptionException
     */
    private function computeEncryptionKeyFingerprint($encryptionCertificate) {
        if(isset($encryptionCertificate)) {
            try {
                $publicKeyPem = openssl_pkey_get_details(openssl_pkey_get_public($encryptionCertificate->getBytes()))['key'];
                $publicKeyDer = EncodingUtils::pemToDer($publicKeyPem, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----');
                $hash = new Hash('sha256');
                $this->encryptionKeyFingerprint = EncodingUtils::encodeBytes($hash->hash($publicKeyDer), FieldValueEncoding::HEX);
            } catch (\Exception $e) {
                throw new EncryptionException('Failed to compute encryption key fingerprint!', $e);
            }
        }
    }

}
