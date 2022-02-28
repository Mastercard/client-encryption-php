<?php

namespace Mastercard\Developer\Encryption\AES;

use phpseclib3\Crypt\AES;

class AESGCM
{
    private function __construct()
    {
    }

    public static function decrypt(string $iv, string $key, string $authTag, string $aad, string $cipherText)
    {
        $cipher = new AES('gcm');
        $cipher->setNonce($iv);
        $cipher->setKey($key);
        $cipher->disablePadding();
        $cipher->setTag($authTag);
        $cipher->setAAD($aad);
        return $cipher->decrypt($cipherText);
    }
}
