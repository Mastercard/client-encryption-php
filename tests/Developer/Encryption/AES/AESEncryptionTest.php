<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\AES\AESEncryption;

use PHPUnit\Framework\TestCase;

class AESEncryptionTest extends TestCase
{
    public function testGenerateCek()
    {
        $cek = AESEncryption::generateCek(256);

        $this->assertEquals(32, strlen($cek));
    }
}
