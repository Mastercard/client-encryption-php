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

    public function testEncryptBytes_InteroperabilityTest() {
        // GIVEN
        $ivValue = 'VNm/scgd1jhWF0z4+Qh6MA==';
        $keyValue = 'mZzmzoURXI3Vk0vdsPkcFw==';
        $dataValue = 'some data ù€@';

        // WHEN
        $encryptedBytes = AESCBC::encrypt(base64_decode($ivValue), base64_decode($keyValue), $dataValue);

        // THEN
        $expectedEncryptedBytes = base64_decode('Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=');
        $this->assertEquals($expectedEncryptedBytes, $encryptedBytes);
    }

    public function testDecryptBytes_InteroperabilityTest() {
        // GIVEN
        $ivValue = 'VNm/scgd1jhWF0z4+Qh6MA==';
        $keyValue = 'mZzmzoURXI3Vk0vdsPkcFw==';
        $encryptedDataValue = 'Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=';

        // WHEN
        $decryptedBytes = AESCBC::decrypt(base64_decode($ivValue), base64_decode($keyValue), base64_decode($encryptedDataValue));

        // THEN
        $expectedBytes = 'some data ù€@';
        $this->assertEquals($expectedBytes, $decryptedBytes);
    }


}
