<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\AES\AESCBC;

use PHPUnit\Framework\TestCase;

class AESCBCTest extends TestCase
{
    public function testDecrypt()
    {
        $result = AESCBC::decrypt(
            EncodingUtils::base64UrlDecode("yI0CS3NdBrz9CCW2jwBSDw"),
            pack("H*", "EC5308E9B72F00B9BAF73C8A953E59AA"),
            EncodingUtils::base64UrlDecode("6zr2pOSmAGdlJG0gbH53Eg")
        );

        $this->assertEquals("bar", $result);
    }
}
