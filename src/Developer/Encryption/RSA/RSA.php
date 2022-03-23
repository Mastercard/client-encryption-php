<?php

namespace Mastercard\Developer\Encryption\RSA;

use Mastercard\Developer\Encryption\EncryptionException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA as CryptRSA;

class RSA
{
    /**
     * @param string    $publicKey 
     * @param string    $toWrap 
     * @param string    $oaepDigestAlgorithm
     * @return string 
     * @throws EncryptionException
     */
    public static function wrapSecretKey($publicKey, $toWrap, $oaepDigestAlgorithm = 'sha256')
    {        
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        try {
            $asymmetricKey = PublicKeyLoader::load($publicKey);

            return $asymmetricKey
                ->withHash($hash)
                ->withPadding(CryptRSA::ENCRYPTION_OAEP)
                ->withMGFHash($hash)
                ->encrypt($toWrap);
        } catch (\Exception $e) {
            throw new EncryptionException("Failed to wrap secret key!", $e);
        }
    }

    /**
     * @param string            $decryptionKey 
     * @param string            $wrapped 
     * @param string            $oaepDigestAlgorithm
     * @param string|false      $password
     * @return string 
     * @throws EncryptionException
     */
    public static function unwrapSecretKey($decryptionKey, $wrapped, $oaepDigestAlgorithm = 'sha256', $password = false)
    {
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        try {
            $asymmetricKey = PublicKeyLoader::load($decryptionKey, $password);

            return $asymmetricKey
                ->withHash($hash)
                ->withPadding(CryptRSA::ENCRYPTION_OAEP)
                ->withMGFHash($hash)
                ->decrypt($wrapped);
        } catch (\Exception $e) {
            throw new EncryptionException("Failed to unwrap secret key!", $e);
        }
    }
}
