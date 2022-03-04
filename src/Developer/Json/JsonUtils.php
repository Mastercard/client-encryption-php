<?php
namespace Mastercard\Developer\Json;

class JsonUtils{

    /**
     * @param string $json
     * @return string
     */
    public static function sanitize(string $json) {
        $json = str_replace("\n", '', $json);
        $json = str_replace("\r", '', $json);
        $json = str_replace("\t", '', $json);
        return str_replace("\r\n", '', $json);
    }

    /**
     * @param mixed $object
     * @return mixed
     */
    public static function toJsonString($object) {
        if (is_null($object)) {
            throw new \InvalidArgumentException('Can\'t get a JSON string from a null object!');
        }
        if (is_string($object)) {
            return $object;
        }
        return json_encode($object);
    }

    /**
     * @param \stdClass $payloadJsonObject
     * @param string    $jsonPath
     * @return mixed
     */
    public static function readJsonElement($payloadJsonObject, $jsonPath) {
        return JsonPath::find($payloadJsonObject, $jsonPath);
    }

    /**
     * @param \stdClass $payloadJsonObject
     * @param string    $jsonPath
     * @throws \InvalidArgumentException
     * @return mixed
     */
    public static function readJsonObject($payloadJsonObject, $jsonPath) {
        $inJsonElement = self::readJsonElement($payloadJsonObject, $jsonPath);
        if (is_null($inJsonElement)) {
            return null;
        }
        if (!is_object($inJsonElement)) {
            throw new \InvalidArgumentException('JSON object expected at path: \'' . $jsonPath . '\'!');
        }
        return $inJsonElement;
    }

    /**
     * @param \stdClass $payloadJsonObject
     * @param string    $jsonPathOut
     * @throws \InvalidArgumentException
     * @return mixed
     */
    public static function checkOrCreateOutObject($payloadJsonObject, $jsonPathOut) {
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

    /**
     * @param \stdClass $object
     * @param string    $key
     * @return mixed
     */
    public static function readAndDeleteJsonKey($object, $key) {
        if (empty($key) || false === property_exists($object, $key)) {
            // Do nothing
            return null;
        }
        $value = $object->$key;
        unset($object->$key);
        return $value;
    }

    /**
     * @param \stdClass $payloadJsonObject
     * @param string    $jsonPathOut
     * @param \stdClass $outJsonObject
     * @param mixed     $decryptedValue
     */
    public static function addDecryptedDataToPayload($payloadJsonObject, $jsonPathOut, $outJsonObject, $decryptedValue) {
        $decryptedValueJsonElement = json_decode($decryptedValue);
        if (is_null($decryptedValueJsonElement)) {
            // 'json_decode' returns null for strings
            $decryptedValueJsonElement = $decryptedValue;
        }

        if ('$' === $jsonPathOut && is_array($decryptedValueJsonElement)) {
            return $decryptedValueJsonElement;
        }

        if (!is_object($decryptedValueJsonElement)) {
            // Array or primitive: overwrite
            $parentPath = JsonPath::getParentPath($jsonPathOut);
            $elementKey = JsonPath::getElementKey($jsonPathOut);
            $parentObject = JsonPath::find($payloadJsonObject, $parentPath);
            $parentObject->$elementKey = $decryptedValueJsonElement;
            return $payloadJsonObject;
        }

        // Object: merge
        foreach ($decryptedValueJsonElement as $key => $value) {
            $outJsonObject->$key = $value;
        }
        return $payloadJsonObject;
    }
}