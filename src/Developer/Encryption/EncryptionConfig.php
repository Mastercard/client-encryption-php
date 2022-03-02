<?php

namespace Mastercard\Developer\Encryption;

abstract class EncryptionConfig
{

    protected function __construct()
    {
    }

    /**
     * The different methods of encryption
     */
    /**
     * The encryption scheme to be used
     */
    private $scheme = EncryptionConfigScheme::LEGACY;

    /**
     * The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: "c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f"
     */
    private string $encryptionKeyFingerprint;

    /**
     * A certificate object whose public key will be used for encryption.
     */
    private $encryptionCertificate;

    /**
     * A private key object to be used for decryption.
     */
    private string $decryptionKey;

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
    private $encryptedValueFieldName = null;

    public function getEncryptionKeyFingerprint(): string
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


    protected function getEncryptionPaths(): array
    {
        return $this->encryptionPaths;
    }

    protected function getDecryptionPaths(): array
    {
        return $this->decryptionPaths;
    }

    protected function getEncryptedValueFieldName(): string
    {
        return $this->encryptedValueFieldName;
    }
}
