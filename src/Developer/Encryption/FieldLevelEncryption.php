<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Json\JsonPath;
use Mastercard\Developer\Utils\EncodingUtils;

/**
 * Performs field level encryption on HTTP payloads.
 * @package Mastercard\Developer\Encryption
 */
class FieldLevelEncryption {

    const SYMMETRIC_CYPHER = 'AES-128-CBC';

    private function __construct() {}

    /**
     * Encrypt parts of a JSON payload using the given parameters and configuration.
     * @param $payload A JSON string
     * @param $config A FieldLevelEncryptionConfig instance
     * @param $params A FieldLevelEncryptionParams instance
     * @see FieldLevelEncryptionConfig
     * @see FieldLevelEncryptionParams
     * @return The updated payload
     * @throws EncryptionException
     */
    public static function encryptPayload($payload, $config, $params = null) {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            // Perform encryption (if needed)
            foreach ($config->encryptionPaths as $jsonPathIn => $jsonPathOut) {
                self::encryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params);
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
     * @param $payload A JSON string
     * @param $config A FieldLevelEncryptionConfig instance
     * @param $params A FieldLevelEncryptionParams instance
     * @see FieldLevelEncryptionConfig
     * @see FieldLevelEncryptionParams
     * @return The updated payload
     * @throws EncryptionException
     */
    public static function decryptPayload($payload, $config, $params = null) {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            // Perform decryption (if needed)
            foreach ($config->decryptionPaths as $jsonPathIn => $jsonPathOut) {
                self::decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params);
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
     * @throws EncryptionException
     */
    private static function encryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params) {

        $inJsonObject = self::readJsonElement($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to encrypt
            return;
        }

        if (empty($params)) {
            // Generate encryption params
            $params = FieldLevelEncryptionParams::generate($config);
        }

        // Encrypt data at the given JSON path
        $inJsonString = self::sanitizeJson(json_encode($inJsonObject));
        $encryptedValueBytes = self::encryptBytes($params->getSecretKeyBytes(), $params->getIvBytes(), $inJsonString);
        $encryptedValue = EncodingUtils::encodeBytes($encryptedValueBytes, $config->fieldValueEncoding);

        // Delete data in clear
        if ('$' !== $jsonPathIn) {
            JsonPath::delete($payloadJsonObject, $jsonPathIn);
        } else {
            // Delete keys one by one
            foreach ($inJsonObject as $key => $value) {
                unset($inJsonObject->$key);
            }
        }

        // Add encrypted data and encryption fields at the given JSON path
        $outJsonObject = self::checkOrCreateOutObject($payloadJsonObject, $jsonPathOut);
        $outJsonObject->{$config->encryptedValueFieldName} = $encryptedValue;
        if (!empty($config->ivFieldName)) {
            $outJsonObject->{$config->ivFieldName} = $params->getIvValue();
        }
        if (!empty($config->encryptedKeyFieldName)) {
            $outJsonObject->{$config->encryptedKeyFieldName} = $params->getEncryptedKeyValue();
        }
        if (!empty($config->encryptionCertificateFingerprintFieldName)) {
            $outJsonObject->{$config->encryptionCertificateFingerprintFieldName} = $params->getEncryptionCertificateFingerprintValue();
        }
        if (!empty($config->encryptionKeyFingerprintFieldName)) {
            $outJsonObject->{$config->encryptionKeyFingerprintFieldName} = $params->getEncryptionKeyFingerprintValue();
        }
        if (!empty($config->oaepPaddingDigestAlgorithmFieldName)) {
            $outJsonObject->{$config->oaepPaddingDigestAlgorithmFieldName} = $params->getOaepPaddingDigestAlgorithmValue();
        }
    }

    /**
     * @throws EncryptionException
     */
    private static function decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config, $params) {

        $inJsonObject = self::readJsonObject($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to decrypt
            return;
        }

        // Read and remove encrypted data and encryption fields at the given JSON path
        $encryptedValueJsonElement = self::readAndDeleteJsonKey($inJsonObject, $config->encryptedValueFieldName);
        if (empty($encryptedValueJsonElement)) {
            // Nothing to decrypt
            return;
        }

        if (!$config->useHttpPayloads() && empty($params)) {
            throw new \InvalidArgumentException('Encryption params have to be set when not stored in HTTP payloads!');
        }

        if (empty($params)) {
            // Read encryption params from the payload
            $oaepDigestAlgorithmJsonElement = self::readAndDeleteJsonKey($inJsonObject, $config->oaepPaddingDigestAlgorithmFieldName);
            $oaepDigestAlgorithm = empty($oaepDigestAlgorithmJsonElement) ? $config->oaepPaddingDigestAlgorithm : $oaepDigestAlgorithmJsonElement;
            $encryptedKeyJsonElement = self::readAndDeleteJsonKey($inJsonObject, $config->encryptedKeyFieldName);
            $ivJsonElement = self::readAndDeleteJsonKey($inJsonObject, $config->ivFieldName);
            self::readAndDeleteJsonKey($inJsonObject, $config->encryptionCertificateFingerprintFieldName);
            self::readAndDeleteJsonKey($inJsonObject, $config->encryptionKeyFingerprintFieldName);
            $params = new FieldLevelEncryptionParams($config, $ivJsonElement, $encryptedKeyJsonElement, $oaepDigestAlgorithm);
        }

        // Decrypt data
        $encryptedValueBytes = EncodingUtils::decodeValue($encryptedValueJsonElement, $config->fieldValueEncoding);
        $decryptedValueBytes = self::decryptBytes($params->getSecretKeyBytes(), $params->getIvBytes(), $encryptedValueBytes);

       // Add decrypted data at the given JSON path
        $decryptedValue = self::sanitizeJson($decryptedValueBytes);
        $outJsonObject = self::checkOrCreateOutObject($payloadJsonObject, $jsonPathOut);
        self::addDecryptedDataToPayload($payloadJsonObject, $jsonPathOut, $outJsonObject, $decryptedValue);

        // Remove the input if now empty
        if (empty((array)$inJsonObject) && '$' !== $jsonPathIn) {
            JsonPath::delete($payloadJsonObject, $jsonPathIn);
        }
    }

    private static function addDecryptedDataToPayload($payloadJsonObject, $jsonPathOut, $outJsonObject, $decryptedValue) {
        $decryptedValueJsonElement = json_decode($decryptedValue);
        if (is_null($decryptedValueJsonElement)) {
            // 'json_decode' returns null for strings
            $decryptedValueJsonElement = $decryptedValue;
        }
        if (!is_object($decryptedValueJsonElement)) {
            // Array or primitive: overwrite
            $parentPath = JsonPath::getParentPath($jsonPathOut);
            $elementKey = JsonPath::getElementKey($jsonPathOut);
            $parentObject = JsonPath::find($payloadJsonObject, $parentPath);
            $parentObject->$elementKey = $decryptedValueJsonElement;
            return;
        }

        // Object: merge
        foreach ($decryptedValueJsonElement as $key => $value) {
            $outJsonObject->$key = $value;
        }
    }
    
    private static function readJsonElement($payloadJsonObject, $jsonPath) {
        return JsonPath::find($payloadJsonObject, $jsonPath);
    }

    private static function readJsonObject($payloadJsonObject, $jsonPath) {
        $inJsonElement = self::readJsonElement($payloadJsonObject, $jsonPath);
        if (is_null($inJsonElement)) {
            return null;
        }
        if (!is_object($inJsonElement)) {
            throw new \InvalidArgumentException('JSON object expected at path: \'' . $jsonPath . '\'!');
        }
        return $inJsonElement;
    }

    private static function checkOrCreateOutObject($payloadJsonObject, $jsonPathOut) {
        $outJsonObject = self::readJsonObject($payloadJsonObject, $jsonPathOut);
        if (!is_null($outJsonObject)) {
            // Object already exists
            return $outJsonObject;
        }

        // Path does not exist: if parent exists then we create a new object under the parent
        $parentJsonPath = JsonPath::getParentPath($jsonPathOut);
        $parentJsonObject = self::readJsonObject($payloadJsonObject, $parentJsonPath);
        if (is_null($parentJsonObject)) {
            throw new \InvalidArgumentException('Parent path not found in payload: \'' . $parentJsonPath . '\'!');
        }
        $elementKey = JsonPath::getElementKey($jsonPathOut);
        $parentJsonObject->$elementKey = json_decode('{}');
        return $parentJsonObject->$elementKey;
    }

    private static function readAndDeleteJsonKey($object, $key) {
        if (empty($key) || false === property_exists($object, $key)) {
            // Do nothing
            return null;
        }
        $value = $object->$key;
        unset($object->$key);
        return $value;
    }

    private static function encryptBytes($key, $iv, $bytes) {
        return openssl_encrypt($bytes, self::SYMMETRIC_CYPHER, $key, OPENSSL_RAW_DATA, $iv);
    }

    private static function decryptBytes($key, $iv, $bytes) {
        return openssl_decrypt($bytes, self::SYMMETRIC_CYPHER, $key, OPENSSL_RAW_DATA, $iv);
    }

    private static function sanitizeJson($json) {
        $json = str_replace("\n", '', $json);
        $json = str_replace("\r", '', $json);
        $json = str_replace("\t", '', $json);
        return str_replace("\r\n", '', $json);
    }
}