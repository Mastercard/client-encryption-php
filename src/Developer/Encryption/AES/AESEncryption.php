<?php

namespace Mastercard\Developer\Encryption\AES;

class AESEncryption
{
    private function __construct()
    {
        // Nothing to do here
    }

    public static function generateIv(string $cipher_algo = 'AES-128-CBC')
    {
        $ivLength = openssl_cipher_iv_length($cipher_algo);
        $iv = openssl_random_pseudo_bytes($ivLength);

        return $iv;
    }

    public static function generateCek(int $bitLength)
    {
        return openssl_random_pseudo_bytes($bitLength / 8);
    }
}
