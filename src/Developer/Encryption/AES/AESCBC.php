<?php

namespace Mastercard\Developer\Encryption\AES;

use Mastercard\Developer\Encryption\EncryptionException;
use phpseclib3\Crypt\AES;

class AESCBC
{
    private function __construct(){
        // This class can't be instantiated
    }

    /**
     * @param string $iv
     * @param string $key
     * @param string $bytes
     * @throws EncryptionException
     * @return string
     */
    public static function encrypt($iv, $key, $bytes) {
        $aes = new AES('cbc');
        $aes->setKey($key);
        $aes->setIV($iv);
        $encryptedBytes = $aes->encrypt($bytes);
        if (false === $encryptedBytes) {
            throw new EncryptionException('Failed to encrypt bytes!');
        }
        return $encryptedBytes;
    }

    /**
     * @param string $iv
     * @param string $key
     * @param string $encryptedBytes
     * @throws EncryptionException
     * @return string
     */
    public static function decrypt($iv, $key, $encryptedBytes) {
        $aes = new AES('cbc');
        $aes->setKey($key);
        $aes->setIV($iv);
        $bytes = $aes->decrypt($encryptedBytes);
        if (false === $bytes) {
            throw new EncryptionException('Failed to decrypt bytes with the provided key and IV!');
        }
        return $bytes;
    }    
}
