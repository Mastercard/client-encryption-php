<?php

namespace Mastercard\Developer\Encryption;

class JweConfig extends EncryptionConfig
{
    public function __construct()
    {
        $this->scheme = EncryptionConfigScheme::JWE;
    }
}
