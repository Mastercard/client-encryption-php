<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\AES\AESEncryption;

use PHPUnit\Framework\TestCase;

class AESEncryptionTest extends TestCase
{
    public function testGenerateRandomBytes()
    {
        $mock = \Phake::mock(AESEncryption::class);

        $bitLength = 256;

        \Phake::whenStatic($mock)->generateRandomBytes($bitLength)->thenCallParent();

        $result = \Phake::makeStaticsVisible($mock)->generateRandomBytes($bitLength);

        $this->assertEquals(64, strlen(bin2hex($result)));
    }

    public function testGenerateCek()
    {
        $cek = AESEncryption::generateCek(256);

        $this->assertEquals("AES", $cek["algorithm"]);
        $this->assertEquals(32, strlen($cek["key"]));
    }
}
