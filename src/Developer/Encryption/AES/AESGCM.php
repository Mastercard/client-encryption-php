<?php

namespace Mastercard\Developer\Encryption\AES;

use phpseclib3\Crypt\AES;

class AESGCM
{
    private function __construct()
    {
    }

    /**
     * @param string $iv
     * @param string $key
     * @param string $authTag
     * @param string $aad
     * @param string $cipherText
     * @return string
     */
    public static function decrypt($iv, $key, $authTag, $aad, $cipherText)
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
