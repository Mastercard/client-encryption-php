<?php

namespace Mastercard\Developer\Encryption;

abstract class EncryptionConfig
{
    /**
     * The different methods of encryption
     */
    /**
     * The encryption scheme to be used
     */
    protected $scheme = EncryptionConfigScheme::LEGACY;

    /**
     * The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: "c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f"
     */
    protected string|null $encryptionKeyFingerprint = null;

    /**
     * A certificate object whose public key will be used for encryption.
     */
    protected $encryptionCertificate;

    /**
     * A private key object to be used for decryption.
     */
    protected string|null $decryptionKey = null;

    /**
     * A list of JSON paths to encrypt in request payloads.
     * Example:
     * <pre>
     * new HashMap<>() {
     *     {
     *         put("$.path.to.element.to.be.encrypted", "$.path.to.object.where.to.store.encryption.fields");
     *     }
     * }
     * </pre>
     */
    private array $encryptionPaths = [];

    /**
     * A list of JSON paths to decrypt in response payloads.
     * Example:
     * <pre>
     * new HashMap<>() {
     *     {
     *         put("$.path.to.object.with.encryption.fields", "$.path.where.to.write.decrypted.element");
     *     }
     * }
     * </pre>
     */
    private array $decryptionPaths = [];

    /**
     * The name of the payload field where to write/read the encrypted data value.
     */
    protected $encryptedValueFieldName = null;

    public function getEncryptionKeyFingerprint(): string|null
    {
        return $this->encryptionKeyFingerprint;
    }

    public function getEncryptionCertificate()
    {
        return $this->encryptionCertificate;
    }

    public function getDecryptionKey(): string
    {
        return $this->decryptionKey;
    }

    public function getScheme(): int
    {
        return $this->scheme;
    }

    public function setEncryptionKeyFingerprint(string|null $encryptionKeyFingerprint)
    {
        $this->encryptionKeyFingerprint = $encryptionKeyFingerprint;
    }

    public function setEncryptionCertificate($encryptionCertificate)
    {
        $this->encryptionCertificate = $encryptionCertificate;
    }

    public function setDecryptionKey(string|null $decryptionKey)
    {
        $this->decryptionKey = $decryptionKey;
    }

    public function setEncryptedValueFieldName($encryptedValueFieldName)
    {
        $this->encryptedValueFieldName = $encryptedValueFieldName;
    }

    public function setEncryptionPaths(array $encryptionPaths)
    {
        $this->encryptionPaths = $encryptionPaths;
    }

    public function setDecryptionPaths(array $decryptionPaths)
    {
        $this->decryptionPaths = $decryptionPaths;
    }

    public function getEncryptionPaths(): array
    {
        return $this->encryptionPaths;
    }

    public function getDecryptionPaths(): array
    {
        return $this->decryptionPaths;
    }

    public function getEncryptedValueFieldName(): string
    {
        return $this->encryptedValueFieldName;
    }
    
}
