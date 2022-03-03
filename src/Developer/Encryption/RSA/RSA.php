<?php

namespace Mastercard\Developer\Encryption\RSA;

use Mastercard\Developer\Encryption\EncryptionException;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA as CryptRSA;

class RSA
{
    public static function wrapSecretKey(string $publicKey, string $toWrap, string $oaepDigestAlgorithm = 'sha256')
    {
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        try{
            $asymmetricKey = PublicKeyLoader::load($publicKey);

            return $asymmetricKey
            ->withHash($hash)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($hash)
            ->encrypt($toWrap);
        }catch(\Exception $e){
            throw new EncryptionException("Failed to wrap secret key!", $e);
        }
    }

    public static function unwrapSecretKey(string $decryptionKey, string $wrapped, string $oaepDigestAlgorithm = 'sha256', string|false $password = false)
    {
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        try{
            $asymmetricKey = PublicKeyLoader::load($decryptionKey, $password);

            return $asymmetricKey
            ->withHash($hash)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($hash)
            ->decrypt($wrapped);
        }catch(\Exception $e){
            throw new EncryptionException("Failed to unwrap secret key!", $e);
        }            
    }
}
