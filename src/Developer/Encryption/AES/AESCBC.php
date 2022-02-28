<?php

namespace Mastercard\Developer\Encryption\AES;

class AESCBC
{
    private function __construct()
    {
    }

    public static function decrypt(string $iv, string $key, string $authTag, string $aad, string $cipherText)
    {
        // NEED TO IMPLEMENT
        return null;
    }
}
