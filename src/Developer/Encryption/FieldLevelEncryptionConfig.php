<?php

namespace Mastercard\Developer\Encryption;

/**
 * A class for storing the encryption/decryption configuration.
 * @package Mastercard\Developer\Encryption
 */
class FieldLevelEncryptionConfig {

    /**
     * A certificate object whose public key will be used for encryption.
     */
    public $encryptionCertificate;

    /**
     * The SHA-256 hex-encoded digest of the certificate used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: '4d9d7540be320429ffc8e6506f054525816e2d0e95a85247d5b58be713f28be0'
     */
    public $encryptionCertificateFingerprint;

    /**
     * The SHA-256 hex-encoded digest of the key used for encryption (optional, the digest will be
     * automatically computed if this field is null or empty).
     * Example: 'c3f8ef7053c4fb306f7476e7d1956f0aa992ff9dfdd5244b912a1d377ff3a84f'
     */
    public $encryptionKeyFingerprint;

    /**
     * A private key object to be used for decryption.
     */
    public $decryptionKey;

    /**
     * A list of JSON paths to encrypt in request payloads.
     * Example:
     * <pre>
     * array(
     *     '$.path.to.element.to.be.encrypted' => '$.path.to.object.where.to.store.encryption.fields'
     * )
     * </pre>
     */
    public $encryptionPaths = array();

    /**
     * A list of JSON paths to decrypt in response payloads.
     * Example:
     * <pre>
     * array(
     *     '$.path.to.object.with.encryption.fields' => '$.path.where.to.write.decrypted.element'
     * )
     * </pre>
     */
    public $decryptionPaths = array();

    /**
     * The digest algorithm to be used for the RSA OAEP padding. Example: 'SHA-512'.
     */
    public $oaepPaddingDigestAlgorithm;

    /**
     * The name of the payload field where to write/read the digest algorithm used for
     * the RSA OAEP padding (optional, the field won't be set if the name is null or empty).
     */
    public $oaepPaddingDigestAlgorithmFieldName;

    /**
     * The name of the HTTP header where to write/read the digest algorithm used for
     * the RSA OAEP padding (optional, the header won't be set if the name is null or empty).
     */
    public $oaepPaddingDigestAlgorithmHeaderName;

    /**
     * The name of the payload field where to write/read the initialization vector value.
     */
    public $ivFieldName;

    /**
     * The name of the header where to write/read the initialization vector value.
     */
    public $ivHeaderName;

    /**
     * The name of the payload field where to write/read the one-time usage encrypted symmetric key.
     */
    public $encryptedKeyFieldName;

    /**
     * The name of the header where to write/read the one-time usage encrypted symmetric key.
     */
    public $encryptedKeyHeaderName;

    /**
     * The name of the payload field where to write/read the encrypted data value.
     */
    public $encryptedValueFieldName;

    /**
     * The name of the payload field where to write/read the digest of the encryption
     * certificate (optional, the field won't be set if the name is null or empty).
     */
    public $encryptionCertificateFingerprintFieldName;

    /**
     * The name of the header where to write/read the digest of the encryption
     * certificate (optional, the header won't be set if the name is null or empty).
     */
    public $encryptionCertificateFingerprintHeaderName;

    /**
     * The name of the payload field where to write/read the digest of the encryption
     * key (optional, the field won't be set if the name is null or empty).
     */
    public $encryptionKeyFingerprintFieldName;

    /**
     * The name of the header where to write/read the digest of the encryption
     * key (optional, the header won't be set if the name is null or empty).
     */
    public $encryptionKeyFingerprintHeaderName;

    /**
     * How the field/header values have to be encoded.
     */
    public $fieldValueEncoding;

    /**
     * If the encryption parameters must be written to/read from HTTP headers.
     */
    public function useHttpHeaders() {
        return !empty($this->encryptedKeyHeaderName) && !empty($this->ivHeaderName);
    }

    /**
     * If the encryption parameters must be written to/read from HTTP payloads.
     */
    public function useHttpPayloads() {
        return !empty($this->encryptedKeyFieldName) && !empty($this->ivFieldName);
    }

    public function getOaepPaddingDigestAlgorithmHeaderName() {
        return $this->oaepPaddingDigestAlgorithmHeaderName;
    }

    public function getIvHeaderName() {
        return $this->ivHeaderName;
    }

    public function getEncryptedKeyHeaderName() {
        return $this->encryptedKeyHeaderName;
    }

    public function getEncryptionCertificateFingerprintHeaderName() {
        return $this->encryptionCertificateFingerprintHeaderName;
    }

    public function getEncryptionKeyFingerprintHeaderName() {
        return $this->encryptionKeyFingerprintHeaderName;
    }

    public function getEncryptionCertificateFingerprint() {
        return $this->encryptionCertificateFingerprint;
    }

    public function getEncryptionKeyFingerprint() {
        return $this->encryptionKeyFingerprint;
    }
}