<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Encryption\AES\AESCBC;
use Mastercard\Developer\Json\JsonPath;
use Mastercard\Developer\Json\JsonUtils;
use Mastercard\Developer\Utils\EncodingUtils;

/**
 * Performs field level encryption on HTTP payloads.
 * @package Mastercard\Developer\Encryption
 */
class FieldLevelEncryption {

    private function __construct() {
        // This class can't be instantiated
    }

    /**
     * Encrypt parts of a JSON payload using the given parameters and configuration.
     * @param string                          $payload A JSON string
     * @param FieldLevelEncryptionConfig      $config  A FieldLevelEncryptionConfig instance
     * @param FieldLevelEncryptionParams|null $params  A FieldLevelEncryptionParams instance
     * @see FieldLevelEncryptionConfig
     * @see FieldLevelEncryptionParams
     * @return string The updated payload
     * @throws EncryptionException
     */
    public static function encryptPayload($payload, $config, $params = null) {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            // Perform encryption (if needed)
            foreach ($config->getEncryptionPaths() as $jsonPathIn => $jsonPathOut) {
                $payloadJsonObject = self::encryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params);
            }

            // Return the updated payload
            return json_encode($payloadJsonObject);
        } catch (\InvalidArgumentException $e) {
            throw $e;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new EncryptionException('Payload encryption failed!', $e);
        }
    }

    /**
     * Decrypt parts of a JSON payload using the given parameters and configuration.
     * @param string                          $payload A JSON string
     * @param FieldLevelEncryptionConfig      $config  A FieldLevelEncryptionConfig instance
     * @param FieldLevelEncryptionParams|null $params  A FieldLevelEncryptionParams instance
     * @see FieldLevelEncryptionConfig
     * @see FieldLevelEncryptionParams
     * @return string The updated payload
     * @throws EncryptionException
     */
    public static function decryptPayload($payload, $config, $params = null) {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            // Perform decryption (if needed)
            foreach ($config->getDecryptionPaths() as $jsonPathIn => $jsonPathOut) {
                $payloadJsonObject = self::decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params);
            }

            // Return the updated payload
            return json_encode($payloadJsonObject);
        } catch (\InvalidArgumentException $e) {
            throw $e;
        } catch (EncryptionException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new EncryptionException('Payload decryption failed!', $e);
        }
    }

    /**
     * @param \stdClass                       $payloadJsonObject
     * @param string                          $jsonPathIn
     * @param string                          $jsonPathOut
     * @param FieldLevelEncryptionConfig      $config
     * @param FieldLevelEncryptionParams|null $params
     * @throws EncryptionException
     */
    private static function encryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params) {

        $inJsonObject = JsonUtils::readJsonElement($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to encrypt
            return $payloadJsonObject;
        }

        if (empty($params)) {
            // Generate encryption params
            $params = FieldLevelEncryptionParams::generate($config);
        }

        // Encrypt data at the given JSON path
        $inJsonString = JsonUtils::sanitize(JsonUtils::toJsonString($inJsonObject));
        $encryptedValueBytes = AESCBC::encrypt($params->getIvBytes(), $params->getSecretKeyBytes(), $inJsonString);
        $encryptedValue = EncodingUtils::encodeBytes($encryptedValueBytes, $config->getFieldValueEncoding());

        // Delete data in clear
        if ('$' !== $jsonPathIn) {
            JsonPath::delete($payloadJsonObject, $jsonPathIn);
        } else {
            $payloadJsonObject = json_decode('{}');
        }

        // Add encrypted data and encryption fields at the given JSON path
        $outJsonObject = JsonUtils::checkOrCreateOutObject($payloadJsonObject, $jsonPathOut);
        $outJsonObject->{$config->getEncryptedValueFieldName()} = $encryptedValue;
        if (!empty($config->getIvFieldName())) {
            $outJsonObject->{$config->getIvFieldName()} = $params->getIvValue();
        }
        if (!empty($config->getEncryptedKeyFieldName())) {
            $outJsonObject->{$config->getEncryptedKeyFieldName()} = $params->getEncryptedKeyValue();
        }
        if (!empty($config->getEncryptionCertificateFingerprintFieldName())) {
            $outJsonObject->{$config->getEncryptionCertificateFingerprintFieldName()} = $config->getEncryptionCertificateFingerprint();
        }
        if (!empty($config->getEncryptionKeyFingerprintFieldName())) {
            $outJsonObject->{$config->getEncryptionKeyFingerprintFieldName()} = $config->getEncryptionKeyFingerprint();
        }
        if (!empty($config->getOaepPaddingDigestAlgorithmFieldName())) {
            $outJsonObject->{$config->getOaepPaddingDigestAlgorithmFieldName()} = $params->getOaepPaddingDigestAlgorithmValue();
        }
        return $payloadJsonObject;
    }

    /**
     * @param \stdClass                       $payloadJsonObject
     * @param string                          $jsonPathIn
     * @param string                          $jsonPathOut
     * @param FieldLevelEncryptionConfig      $config
     * @param FieldLevelEncryptionParams|null $params
     * @throws EncryptionException
     */
    private static function decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params) {

        $inJsonObject = JsonUtils::readJsonObject($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to decrypt
            return $payloadJsonObject;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        $encryptedValueJsonElement = JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getEncryptedValueFieldName());
        if (empty($encryptedValueJsonElement)) {
            // Nothing to decrypt
            return $payloadJsonObject;
        }

        if (!$config->useHttpPayloads() && empty($params)) {
            throw new \InvalidArgumentException('Encryption params have to be set when not stored in HTTP payloads!');
        }

        if (empty($params)) {
            // Read encryption params from the payload
            $oaepDigestAlgorithmJsonElement = JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getOaepPaddingDigestAlgorithmFieldName());
            $oaepDigestAlgorithm = empty($oaepDigestAlgorithmJsonElement) ? $config->getOaepPaddingDigestAlgorithm() : $oaepDigestAlgorithmJsonElement;
            $encryptedKeyJsonElement = JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getEncryptedKeyFieldName());
            $ivJsonElement = JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getIvFieldName());
            JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getEncryptionCertificateFingerprintFieldName());
            JsonUtils::readAndDeleteJsonKey($inJsonObject, $config->getEncryptionKeyFingerprintFieldName());
            $params = new FieldLevelEncryptionParams($config, $ivJsonElement, $encryptedKeyJsonElement, $oaepDigestAlgorithm);
        }

        // Decrypt data
        $encryptedValueBytes = EncodingUtils::decodeValue($encryptedValueJsonElement, $config->getFieldValueEncoding());
        $decryptedValueBytes = AESCBC::decrypt($params->getIvBytes(), $params->getSecretKeyBytes(), $encryptedValueBytes);

        // Add decrypted data at the given JSON path
        $decryptedValue = JsonUtils::sanitize($decryptedValueBytes);
        $outJsonObject = JsonUtils::checkOrCreateOutObject($payloadJsonObject, $jsonPathOut);
        $payloadJsonObject = JsonUtils::addDecryptedDataToPayload($payloadJsonObject, $jsonPathOut, $outJsonObject, $decryptedValue);

        // Remove the input if now empty
        $inJsonElement = JsonUtils::readJsonElement($payloadJsonObject, $jsonPathIn);
        if (empty((array)$inJsonElement) && '$' !== $jsonPathIn) {
            JsonPath::delete($payloadJsonObject, $jsonPathIn);
        }
        return $payloadJsonObject;
    }


}
