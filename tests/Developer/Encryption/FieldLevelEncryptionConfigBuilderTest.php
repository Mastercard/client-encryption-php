<?php
namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\FieldLevelEncryptionConfigBuilder;
use Mastercard\Developer\Encryption\FieldValueEncoding;
use Mastercard\Developer\Test\TestUtils;
use PHPUnit\Framework\TestCase;

class FieldLevelEncryptionConfigBuilderTest extends TestCase {

    public function testBuild_ShouldThrowInvalidArgumentException_WhenNotDefiniteDecryptionPath() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('JSON paths for decryption must point to a single item!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withDecryptionPath('$.encryptedPayloads[*]', '$.payload')
            ->withDecryptionKey(TestUtils::getTestDecryptionKey())
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingDecryptionKey() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Can\'t decrypt without decryption key!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withDecryptionPath('$.encryptedPayload', '$.payload')
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenNotDefiniteEncryptionPath() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('JSON paths for encryption must point to a single item!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withEncryptionPath('$.payloads[*]', '$.encryptedPayload')
            ->withEncryptionCertificate(TestUtils::getTestEncryptionCertificate())
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingEncryptionCertificate() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Can\'t encrypt without encryption key!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withEncryptionPath('$.payload', '$.encryptedPayload')
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingOaepPaddingDigestAlgorithm() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The digest algorithm for OAEP cannot be empty!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenUnsupportedOaepPaddingDigestAlgorithm() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported OAEP digest algorithm: SHA-720!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-720')
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingEncryptedValueFieldName() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Encrypted value field name cannot be empty!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingBothEncryptedKeyFieldNameAndHeaderName() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one of encrypted key field name or encrypted key header name must be set!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingBothIvFieldNameAndHeaderName() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('At least one of IV field name or IV header name must be set!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenMissingFieldValueEncoding() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Value encoding for fields and headers cannot be empty!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenEncryptedKeyAndIvHeaderNamesNotBothSetOrUnset() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('IV header name and encrypted key header name must be both set or both unset!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyHeaderName('x-encrypted-key')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withIvFieldName('iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_ShouldThrowInvalidArgumentException_WhenEncryptedKeyAndIvFieldNamesNotBothSetOrUnset() {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('IV field name and encrypted key field name must be both set or both unset!');
        FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withEncryptedKeyHeaderName('x-encrypted-key')
            ->withIvHeaderName('x-iv')
            ->withFieldValueEncoding(FieldValueEncoding::HEX)
            ->build();
    }

    public function testBuild_Nominal() {
        $config = FieldLevelEncryptionConfigBuilder::aFieldLevelEncryptionConfig()
            ->withEncryptionPath('$.payload', '$.encryptedPayload')
            ->withEncryptionCertificate(TestUtils::getTestEncryptionCertificate())
            ->withEncryptionCertificateFingerprint('97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B')
            ->withEncryptionKeyFingerprint('F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810')
            ->withEncryptionCertificateFingerprintFieldName('publicCertificateFingerprint')
            ->withEncryptionCertificateFingerprintHeaderName('x-public-certificate-fingerprint')
            ->withEncryptionKeyFingerprintFieldName('publicKeyFingerprint')
            ->withEncryptionKeyFingerprintHeaderName('x-public-key-fingerprint')
            ->withDecryptionPath('$.encryptedPayload', '$.payload')
            ->withDecryptionKey(TestUtils::getTestDecryptionKey())
            ->withOaepPaddingDigestAlgorithm('SHA-512')
            ->withOaepPaddingDigestAlgorithmFieldName('oaepPaddingDigestAlgorithm')
            ->withOaepPaddingDigestAlgorithmHeaderName('x-oaep-padding-digest-algorithm')
            ->withEncryptedValueFieldName('encryptedValue')
            ->withEncryptedKeyFieldName('encryptedKey')
            ->withEncryptedKeyHeaderName('x-encrypted-key')
            ->withIvFieldName('iv')
            ->withIvHeaderName('x-iv')
            ->withFieldValueEncoding(FieldValueEncoding::BASE64)
            ->build();
        $this->assertNotEmpty($config);
        $this->assertEquals(1, sizeof($config->encryptionPaths));
        $this->assertNotEmpty($config->encryptionCertificate);
        $this->assertEquals('97A2FFE9F0D48960EF31E87FCD7A55BF7843FB4A9EEEF01BDB6032AD6FEF146B', $config->encryptionCertificateFingerprint);
        $this->assertEquals('F806B26BC4870E26986C70B6590AF87BAF4C2B56BB50622C51B12212DAFF2810', $config->encryptionKeyFingerprint);
        $this->assertEquals('publicCertificateFingerprint', $config->encryptionCertificateFingerprintFieldName);
        $this->assertEquals('x-public-certificate-fingerprint', $config->encryptionCertificateFingerprintHeaderName);
        $this->assertEquals('publicKeyFingerprint', $config->encryptionKeyFingerprintFieldName);
        $this->assertEquals('x-public-key-fingerprint', $config->encryptionKeyFingerprintHeaderName);
        $this->assertEquals(1, sizeof($config->decryptionPaths));
        $this->assertNotEmpty($config->decryptionKey);
        $this->assertEquals('SHA-512', $config->oaepPaddingDigestAlgorithm);
        $this->assertEquals('encryptedValue', $config->encryptedValueFieldName);
        $this->assertEquals('encryptedKey', $config->encryptedKeyFieldName);
        $this->assertEquals('x-encrypted-key', $config->encryptedKeyHeaderName);
        $this->assertEquals('iv', $config->ivFieldName);
        $this->assertEquals('x-iv', $config->ivHeaderName);
        $this->assertEquals('oaepPaddingDigestAlgorithm', $config->oaepPaddingDigestAlgorithmFieldName);
        $this->assertEquals('x-oaep-padding-digest-algorithm', $config->oaepPaddingDigestAlgorithmHeaderName);
        $this->assertEquals(FieldValueEncoding::BASE64, $config->fieldValueEncoding);
    }
}