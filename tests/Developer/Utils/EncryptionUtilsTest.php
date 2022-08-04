<?php
namespace Mastercard\Developer\Utils;

use PHPUnit\Framework\TestCase;
use ReflectionClass;

class EncryptionUtilsTest extends TestCase {

    public function testConstruct_ShouldBePrivate() {
        // GIVEN
        $class = new ReflectionClass('Mastercard\Developer\Utils\EncryptionUtils');
        $constructor = $class->getConstructor();

        // WHEN
        $isPrivate = $constructor->isPrivate();

        // THEN
        $this->assertTrue($isPrivate);

        // COVERAGE
        $constructor->setAccessible(true);
        $constructor->invoke($class->newInstanceWithoutConstructor());
    }

    public function testLoadEncryptionCertificate() {
        // GIVEN
        $certificatePath = './resources/Certificates/test_certificate-2048.pem';

        // WHEN
        $certificate = EncryptionUtils::loadEncryptionCertificate($certificatePath);

        // THEN
        $this->assertNotEmpty($certificate);
        $this->assertNotFalse($certificate);
    }

    public function testLoadDecryptionKey() {
        // GIVEN
        $keyContainerPath = './resources/Keys/Pkcs12/test_key.p12';
        $keyAlias = 'mykeyalias';
        $keyPassword = 'Password1';

        // WHEN
        $privateKey = EncryptionUtils::loadDecryptionKey($keyContainerPath, $keyAlias, $keyPassword);

        // THEN
        $this->assertNotEmpty($privateKey);
        $this->assertNotFalse($privateKey);
        $this->assertEquals($keyAlias, $privateKey->getAlias());
        $this->assertEquals($keyPassword, $privateKey->getPassword());
    }
}
