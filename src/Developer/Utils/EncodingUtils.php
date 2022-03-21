<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\FieldValueEncoding;

class EncodingUtils
{

    private function __construct()
    {
        // This class can't be instantiated
    }


    /**
     * @param string            $data 
     * @param bool              $strict 
     * @return string|false
     */
    public static function base64UrlDecode($data, $strict = false)
    {
        // Convert Base64URL to Base64 by replacing “-” with “+” and “_” with “/”
        $b64 = strtr($data, '-_', '+/');

        // Decode Base64 string and return the original data
        return base64_decode($b64, $strict);
    }

    /**
     * @param string            $text 
     * @return string
     */
    public static function base64UrlEncode($text)
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($text)
        );
    }


    /**
     * @param string|null $bytes
     * @param int         $encoding
     * @return string
     * @throws \InvalidArgumentException
     */
    static function encodeBytes($bytes, $encoding)
    {
        return $encoding === FieldValueEncoding::HEX ? self::hexEncode($bytes) : base64_encode($bytes);
    }

    /**
     * @param string|null $value
     * @param int         $encoding
     * @return string|false
     * @throws \InvalidArgumentException
     */
    static function decodeValue($value, $encoding)
    {
        return $encoding === FieldValueEncoding::HEX ? self::hexDecode($value) : base64_decode($value);
    }

    /**
     * @param string|null $bytes
     * @return string
     * @throws \InvalidArgumentException
     */
    static function hexEncode($bytes)
    {
        if ('' === $bytes) {
            return '';
        }
        if (empty($bytes)) {
            throw new \InvalidArgumentException('Can\'t hex encode an empty value!');
        }
        return bin2hex($bytes);
    }

    /**
     * @param string|null $value
     * @return string|false
     * @throws \InvalidArgumentException
     */
    static function hexDecode($value)
    {
        if ('' === $value) {
            return '';
        }
        if (empty($value)) {
            throw new \InvalidArgumentException('Can\'t hex decode an empty value!');
        }
        if (!ctype_xdigit($value)) {
            throw new \InvalidArgumentException('The provided value is not an hex string!');
        }
        return hex2bin($value);
    }

    /**
     * @param string $der
     * @param string $header
     * @param string $footer
     * @return string
     */
    static function derToPem($der, $header, $footer)
    {
        return $header . "\r\n" . chunk_split(base64_encode($der), 64, "\r\n") . $footer;
    }

    /**
     * @param string $pem
     * @param string $header
     * @param string $footer
     * @return string|false
     */
    static function pemToDer($pem, $header, $footer)
    {
        $der = str_replace($header, '', $pem);
        $der = str_replace($footer, '', $der);
        return base64_decode($der);
    }
}
