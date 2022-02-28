<?php

namespace Mastercard\Developer\Encryption\AES;

use phpseclib3\Crypt\AES;

class AESCBC
{
    private function __construct()
    {
    }

    public static function decrypt(string $iv, string $key, string $cipherText)
    {
        $cipher = new AES('cbc');
        $cipher->setIV($iv);
        $cipher->setKey($key);
        return $cipher->decrypt($cipherText);
    }
}
