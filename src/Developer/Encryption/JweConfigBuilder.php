<?php

namespace Mastercard\Developer\Encryption;

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
        $this->computeEncryptionKeyFingerprintWhenNeeded();
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
}
