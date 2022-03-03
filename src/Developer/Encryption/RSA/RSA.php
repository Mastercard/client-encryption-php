<?php

namespace Mastercard\Developer\Encryption\RSA;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA as CryptRSA;

class RSA
{
    public static function wrapSecretKey(string $publicKey, string $toWrap, string $oaepDigestAlgorithm = 'sha256')
    {
        $asymmetricKey = PublicKeyLoader::load($publicKey);
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        return $asymmetricKey
            ->withHash($hash)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($hash)
            ->encrypt($toWrap);
    }

    public static function unwrapSecretKey(string $decryptionKey, string $wrapped, string $oaepDigestAlgorithm = 'sha256')
    {
        $asymmetricKey = PublicKeyLoader::load($decryptionKey);
        $hash = strtolower(str_replace('-', '', $oaepDigestAlgorithm));

        return $asymmetricKey
            ->withHash($hash)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($hash)
            ->decrypt($wrapped);
    }
}
