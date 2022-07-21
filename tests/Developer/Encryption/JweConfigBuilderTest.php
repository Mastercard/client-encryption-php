<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Keys\DecryptionKey;
use Mastercard\Developer\Keys\EncryptionKey;
use PHPUnit\Framework\TestCase;

class JweConfigBuilderTest extends TestCase
{
    public function testBuild_Nominal() {
        
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withDecryptionKey($decryptionKey)
            ->withEncryptionPath("$", "$")
            ->withDecryptionPath("$.encryptedPayload", "$")
            ->withEncryptedValueFieldName("encryptedPayload")
            ->build();

        $this->assertNotEmpty($config);
        $this->assertEquals(EncryptionConfigScheme::JWE, $config->getScheme());
        $this->assertEquals($decryptionKey, $config->getDecryptionKey());
        $this->assertEquals($encryptionCerificate->getBytes(), $config->getEncryptionCertificate()->getBytes());
        $this->assertEquals("encryptedPayload", $config->getEncryptedValueFieldName());
        $this->assertEquals(["$.encryptedPayload" => "$"], $config->getDecryptionPaths());
        $this->assertEquals(["$" => "$"], $config->getEncryptionPaths());
    }

    public function testBuild_ResultShouldBeAssignableToGenericEncryptionConfig() {
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withDecryptionKey($decryptionKey)
            ->build();

        $this->assertNotNull($config);
    }

    public function testBuild_ShouldComputeCertificateKeyFingerprint_WhenFingerprintNotSet() {
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withDecryptionKey($decryptionKey)
            ->build();
            
        $this->assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", $config->getEncryptionKeyFingerprint());
    }

    public function testIntercept_ShouldThrowEncryptionException_WhenInvalidEncryptionCertificate() {
        $this->expectException("Mastercard\Developer\Encryption\EncryptionException");
        $this->expectExceptionMessage("Failed to compute encryption key fingerprint!");

        JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionPath("$.foo", "$.encryptedFoo")
            ->withEncryptionCertificate(EncryptionKey::create("Invalid certificate")) // Invalid certificate
            ->build();
    }

    public function testBuild_ShouldFallbackToDefaults() {
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
                ->withEncryptionCertificate($encryptionCerificate)
                ->build();

        $this->assertEquals(["$.encryptedData" => "$"], $config->getDecryptionPaths());
        $this->assertEquals(["$" => "$"], $config->getEncryptionPaths());
        $this->assertEquals("encryptedData", $config->getEncryptedValueFieldName());
    }

    public function testBuild_ShouldThrowIllegalArgumentException_WhenMissingDecryptionKey() {
        $this->expectException("\InvalidArgumentException");
        $this->expectExceptionMessage("JSON paths for decryption must point to a single item!");

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");
        
        JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionPath("$.encryptedPayloads[*]", "$.payload")
            ->withDecryptionKey($decryptionKey)
            ->build();
    }

    public function testBuild_ShouldThrowIllegalArgumentException_WhenNotDefiniteEncryptionPath() {
        $this->expectException("\InvalidArgumentException");
        $this->expectExceptionMessage("JSON paths for decryption must point to a single item!");

        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");

        JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionPath("$.payloads[*]", "$.encryptedPayload")
            ->withEncryptionCertificate($encryptionCerificate)
            ->build();
    }
}
