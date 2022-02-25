<?php

namespace Mastercard\Developer\Encryption\RSA;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA as CryptRSA;

class RSA
{
    public static function wrapSecretKey(string $publicKey, string $toWrap, string $oaepDigestAlgorithm = 'sha256')
    {
        $asymmetricKey = PublicKeyLoader::load($publicKey);

        return $asymmetricKey
            ->withHash($oaepDigestAlgorithm)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($oaepDigestAlgorithm)
            ->encrypt($toWrap);
    }

    public static function unwrapSecretKey(string $decryptionKey, string $wrapped, string $oaepDigestAlgorithm = 'sha256')
    {
        $asymmetricKey = PublicKeyLoader::load($decryptionKey);

        return $asymmetricKey
            ->withHash($oaepDigestAlgorithm)
            ->withPadding(CryptRSA::ENCRYPTION_OAEP)
            ->withMGFHash($oaepDigestAlgorithm)
            ->decrypt($wrapped);
    }
}
