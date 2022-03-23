<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Keys\DecryptionKey;
use Mastercard\Developer\Keys\EncryptionKey;

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
     * @var string|null
     * The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: "c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f"
     */
    protected $encryptionKeyFingerprint = null;

    /**
     * @var EncryptionKey
     * A certificate object whose public key will be used for encryption.
     */
    protected $encryptionCertificate;

    /**
     * @var DecryptionKey
     * A private key object to be used for decryption.
     */
    protected $decryptionKey;

    /**
     * @var array
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
    private $encryptionPaths = [];

    /**
     * @var array
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
    private $decryptionPaths = [];

    /**
     * @var string|null
     * The name of the payload field where to write/read the encrypted data value.
     */
    protected $encryptedValueFieldName = null;

    /**
     * @return string|null
     */
    public function getEncryptionKeyFingerprint()
    {
        return $this->encryptionKeyFingerprint;
    }

    /**
     * @return EncryptionKey
     */    
    public function getEncryptionCertificate()
    {
        return $this->encryptionCertificate;
    }

    /**
     * @return DecryptionKey
     */
    public function getDecryptionKey()
    {
        return $this->decryptionKey;
    }

    /**
     * @return int
     */    
    public function getScheme()
    {
        return $this->scheme;
    }

    /**
     * @return array
     */    
    public function getEncryptionPaths()
    {
        return $this->encryptionPaths;
    }

    /**
     * @return array
     */    
    public function getDecryptionPaths()
    {
        return $this->decryptionPaths;
    }

    /**
     * @return string
     */    
    public function getEncryptedValueFieldName()
    {
        return $this->encryptedValueFieldName;
    }    

    /**
     * @param string|null $encryptionKeyFingerprint 
     */    
    public function setEncryptionKeyFingerprint($encryptionKeyFingerprint)
    {
        $this->encryptionKeyFingerprint = $encryptionKeyFingerprint;
    }

    /**
     * @param string $encryptionCertificate 
     */    
    public function setEncryptionCertificate($encryptionCertificate)
    {
        $this->encryptionCertificate = $encryptionCertificate;
    }

    /**
     * @param string|null $decryptionKey 
     */    
    public function setDecryptionKey($decryptionKey)
    {
        $this->decryptionKey = $decryptionKey;
    }

    /**
     * @param string $encryptedValueFieldName 
     */    
    public function setEncryptedValueFieldName($encryptedValueFieldName)
    {
        $this->encryptedValueFieldName = $encryptedValueFieldName;
    }

    /**
     * @param array $encryptionPaths
     */    
    public function setEncryptionPaths($encryptionPaths)
    {
        $this->encryptionPaths = $encryptionPaths;
    }

    /**
     * @param array $decryptionPaths
     */    
    public function setDecryptionPaths($decryptionPaths)
    {
        $this->decryptionPaths = $decryptionPaths;
    }


    
}
