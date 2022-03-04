<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Encryption\JWE\JweHeader;
use Mastercard\Developer\Encryption\JWE\JweObject;
use Mastercard\Developer\Json\JsonPath;
use Mastercard\Developer\Json\JsonUtils;
use Mastercard\Developer\Utils\EncodingUtils;

class JweEncryption {

    private function __construct() { }

    private const ALGORITHM = "RSA-OAEP-256";
    private const ENCRYPTION = "A256GCM";
    private const CONTENT_TYPE = "application/json";


    /**
     * Encrypt parts of a JSON payload using the given parameters and configuration.
     * @param string                          $payload A JSON string
     * @param JweConfig                       $config  A JweConfig instance
     * @return string The updated payload
     * @throws EncryptionException
     */    
    public static function encryptPayload(string $payload, JweConfig $config): string {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            // Perform encryption
            foreach ($config->getEncryptionPaths() as $jsonPathIn => $jsonPathOut) {
                $payloadJsonObject = self::encryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config);
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
     * @param JweConfig                       $config  A FieldLevelEncryptionConfig instance
     * @return string The updated payload
     * @throws EncryptionException
     */
    public static function decryptPayload($payload, $config) {
        try {
            // Parse the given payload
            $payloadJsonObject = json_decode($payload);

            
            // Perform decryption (if needed)
            foreach ($config->getDecryptionPaths() as $jsonPathIn => $jsonPathOut) {
                $payloadJsonObject = self::decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config);
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
     * @param JweConfig                       $config
     * @throws EncryptionException
     */    
    private static function encryptPayloadPath($payloadJsonObject, string $jsonPathIn, string $jsonPathOut, JweConfig $config){
        $inJsonObject = JsonPath::find($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to encrypt
            return $payloadJsonObject;
        }
        
        $inJsonString = JsonUtils::sanitize(JsonUtils::toJsonString($inJsonObject));
        $myHeader = new JweHeader(self::ALGORITHM, self::ENCRYPTION, $config->getEncryptionKeyFingerprint(), self::CONTENT_TYPE);
        $payload = JweObject::encrypt($config, $inJsonString, $myHeader);

        // Delete data in clear
        if ('$' !== $jsonPathIn) {
            JsonPath::delete($payloadJsonObject, $jsonPathIn);
        } else {
            $payloadJsonObject = json_decode('{}');
        }

        // Add encrypted data and encryption fields at the given JSON path
        $outJsonObject = JsonUtils::checkOrCreateOutObject($payloadJsonObject, $jsonPathOut);
        $outJsonObject->{$config->getEncryptedValueFieldName()} = $payload;

        return $payloadJsonObject;
    }

    /**
     * @param \stdClass                       $payloadJsonObject
     * @param string                          $jsonPathIn
     * @param string                          $jsonPathOut
     * @param JweConfig                       $config
     * @throws EncryptionException
     */
    private static function decryptPayloadPath($payloadJsonObject, $jsonPathIn, $jsonPathOut, $config) {
        $inJsonObject = JsonUtils::readJsonElement($payloadJsonObject, $jsonPathIn);
        if (is_null($inJsonObject)) {
            // Nothing to encrypt
            return $payloadJsonObject;
        }

        $jweObject = JweObject::parse($inJsonObject);
        $decryptedValueBytes = $jweObject->decrypt($config);

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

    // private static readAndDeleteJsonKey(DocumentContext context, \stdClass $obj, string $key) {
    //     context.delete(key);
    //     return object;
    // }

    // private static Object readJsonObject(DocumentContext context, String jsonPathString) {
    //     return readJsonElement(context, jsonPathString);
    // }
}
