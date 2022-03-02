<?php

namespace Mastercard\Developer\Encryption;

class JweConfigBuilder extends EncryptionConfigBuilder {

    /**
     * Get an instance of the builder.
     */
    public static function aJweEncryptionConfig(): JweConfigBuilder {
        return new JweConfigBuilder();
    }

    /**
     * Build a {@link JweConfig}.
     *
     * @throws EncryptionException
     */
    public function build(): JweConfig {
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
     * See: {@link EncryptionConfig#encryptionCertificate}.
     */
    public function withEncryptionCertificate($encryptionCertificate): JweConfigBuilder {
        $this->encryptionCertificate = $encryptionCertificate;
        return $this;
    }

    /**
     * See: {@link EncryptionConfig#decryptionKey}.
     */
    public function withDecryptionKey($decryptionKey): JweConfigBuilder {
        $this->decryptionKey = $decryptionKey;
        return $this;
    }

    /**
     * See: {@link EncryptionConfig#encryptionPaths}.
     */
    public function withEncryptionPath(string $jsonPathIn, string $jsonPathOut): JweConfigBuilder {
        $this->encryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * See: {@link EncryptionConfig#decryptionPaths}.
     */
    public function withDecryptionPath(string $jsonPathIn, string $jsonPathOut): JweConfigBuilder {
        $this->decryptionPaths[$jsonPathIn] = $jsonPathOut;
        return $this;
    }

    /**
     * See: {@link EncryptionConfig#encryptedValueFieldName}.
     */
    public function withEncryptedValueFieldName(string $encryptedValueFieldName): JweConfigBuilder {
        $this->encryptedValueFieldName = $encryptedValueFieldName;
        return $this;
    }

    private function checkParameterValues() {
        if ($this->decryptionKey == null && $this->encryptionCertificate == null) {
            throw new \InvalidArgumentException("You must include at least an encryption certificate or a decryption key");
        }
    }
}
