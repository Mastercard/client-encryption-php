<?php

namespace Mastercard\Developer\Encryption\AES;

class AESEncryption
{
    private function __construct()
    {
        // Nothing to do here
    }

    public static function generateCek(int $bitLength)
    {
        return [
            "key" => self::generateRandomBytes($bitLength),
            "algorithm" => "AES"
        ];
    }

    public static function generateIv()
    {
        return self::generateRandomBytes(128);
    }

    private static function generateRandomBytes(int $bitLength)
    {
        return random_bytes($bitLength / 8);
    }
}
