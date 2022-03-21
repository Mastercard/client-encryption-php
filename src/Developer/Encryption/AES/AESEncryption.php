<?php

namespace Mastercard\Developer\Encryption\AES;

class AESEncryption
{
    private function __construct()
    {
        // Nothing to do here
    }


    /**
     * @param string            $cipher_algo
     * @return string 
     */    
    public static function generateIv($cipher_algo = 'AES-128-CBC')
    {
        $ivLength = openssl_cipher_iv_length($cipher_algo);
        $iv = openssl_random_pseudo_bytes($ivLength);

        return $iv;
    }

    /**
     * @param int            $bitLength
     * @return string 
     */    
    public static function generateCek($bitLength)
    {
        return openssl_random_pseudo_bytes($bitLength / 8);
    }
}
