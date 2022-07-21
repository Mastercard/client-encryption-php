<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Keys\DecryptionKey;
use Mastercard\Developer\Keys\EncryptionKey;
use PHPUnit\Framework\TestCase;

class JweEncryptionTest extends TestCase {
    public function testEncryptPayload_ShouldEncryptRootArrays() {
        // GIVEN
        $payload = "[" .
                "   {}," .
                "   {}" .
                "]";

        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");
        
        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withDecryptionKey($decryptionKey)
            ->withEncryptionPath("$", "$")
            ->withDecryptionPath("$.encryptedData", "$")
            ->build();


        // WHEN
        $encryptedPayload = JweEncryption::encryptPayload($payload, $config);

        // THEN
        $this->assertNotNull(json_encode($encryptedPayload));

        $decrypedPayload = JweEncryption::decryptPayload($encryptedPayload, $config);

        $this->assertJsonStringEqualsJsonString("[{},{}]", $decrypedPayload);
    }

    public function testDecryptPayload_ShouldDecryptRootArrays() {

        // GIVEN
        $encryptedPayload = "{" .
                "    \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb24vanNvbiIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.IcTIce59pgtjODJn4PhR7oK3F-gxcd7dishTrT7T9y5VC0U5ZS_JdMoRe59_UTkJMY8Nykb2rv3Oh_jSDYRmGB_CWMIciXYMLHQptLTF5xI1ZauDPnooDMWoOCBD_d3I0wTJNcM7I658rK0ZWSByVK9YqhEo8UaIf4e6egRHQdZ2_IGKgICwmglv_uXQrYewOWFTKR1uMpya1N50MDnWax2NtnW3SljP3mARUBLBnRmOyubQCg-Mgn8fsOWWXm-KL9RrQq9AF_HJceoJl1rRgzPW7g6SLK6EjiGW_ArTmrLaOHg9bYOY_LrbyokK_M1pMo9qup70DHvjHkMZqIL3aQ.vtma3jBIo2STkquxTUX9PQ.9ZoQG0sFvQ.ms4bW3OFd03neRlex-zZ8w\"" .
                "}";

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");
        
        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->withDecryptionPath("$.encryptedData", "$")
            ->build();
        
        // WHEN
        $decrypedPayload = JweEncryption::decryptPayload($encryptedPayload, $config);

        // THEN
        $this->assertJsonStringEqualsJsonString("[{},{}]", $decrypedPayload);
    }

    public function testSample()
    {
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withDecryptionKey($decryptionKey)
            ->withEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
            ->withDecryptionPath("$.path.to.encryptedFoo.encryptedData", "$.path.to.foo")
            ->build();

        $payload = "{" .
            "    \"path\": {" .
            "        \"to\": {" .
            "            \"foo\": {" .
            "                \"sensitiveField1\": \"sensitiveValue1\"," .
            "                \"sensitiveField2\": \"sensitiveValue2\"" .
            "            }" .
            "        }" .
            "    }" .
            "}";

        $encryptedPayload = JweEncryption::encryptPayload($payload, $config);

        $decryptedPayload = JweEncryption::decryptPayload($encryptedPayload, $config);

        $this->assertEquals(json_encode(json_decode($payload)), $decryptedPayload);
    }
}
