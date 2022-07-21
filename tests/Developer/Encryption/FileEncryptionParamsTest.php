<?php

namespace Mastercard\Developer\Encryption;

use Mastercard\Developer\Test\TestUtils;
use PHPUnit\Framework\TestCase;

class FileEncryptionParamsTest extends TestCase {

    public function testGenerate_Nominal() {

        // GIVEN
        $config = TestUtils::getTestFieldLevelEncryptionConfigBuilder()
            ->withEncryptionCertificateFingerprint(null)
            ->withEncryptionKeyFingerprint(null)
            ->build();

        // WHEN
        $params = FieldLevelEncryptionparams::generate($config);

        // THEN
        $this->assertNotEmpty($params->getIvValue());
        $this->assertTrue(ctype_xdigit($params->getIvValue()));
        $this->assertNotEmpty($params->getIvBytes());
        $this->assertNotEmpty($params->getEncryptedKeyValue());
        $this->assertTrue(ctype_xdigit($params->getEncryptedKeyValue()));
        $this->assertNotEmpty($params->getSecretKeyBytes());
        $this->assertEquals('SHA256', $params->getOaepPaddingDigestAlgorithmValue());
    }

    public function testGetIvBytes_ShouldThrowEncryptionException_WhenFailsToDecodeIV() {

        // GIVEN
        $config = TestUtils::getTestFieldLevelEncryptionConfigBuilder()->build();
        $params = new FieldLevelEncryptionParams($config, 'INVALID VALUE', null);

        // THEN
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decode the provided IV value!');

        // WHEN
        $params->getIvBytes();
    }

    public function testGetSecretKeyBytes_ShouldThrowEncryptionException_WhenFailsToReadEncryptedKey() {

        // GIVEN
        $config = TestUtils::getTestFieldLevelEncryptionConfigBuilder()->build();
        $params = new FieldLevelEncryptionParams($config, null, 'INVALID VALUE');

        // THEN
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Failed to decode and unwrap the provided secret key value!');

        // WHEN
        $params->getSecretKeyBytes();
    }
}
