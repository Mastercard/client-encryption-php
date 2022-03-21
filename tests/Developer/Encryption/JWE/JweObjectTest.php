<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\JWE\JweObject;
use Mastercard\Developer\Encryption\JWE\JweHeader;
use Mastercard\Developer\Encryption\JweConfig;
use Mastercard\Developer\Encryption\JweConfigBuilder;
use PHPUnit\Framework\TestCase;
use Phake;

class JweObjectTest extends TestCase
{
    public function testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsGcmEncrypted()
    {
        $jweObject = JweObject::parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA");

        $mockConfig = Phake::mock(JweConfig::class);

        Phake::when($mockConfig)->getDecryptionKey()
            ->thenReturn(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"));

        $decryptedPayload = $jweObject->decrypt($mockConfig);

        $this->assertEquals("{\"foo\":\"bar\"}", $decryptedPayload);
    }

    public function  testDecrypt_ShouldReturnDecryptedPayload_WhenPayloadIsCbcEncrypted()
    {
        $jweObject = JweObject::parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ");

        $mockConfig = Phake::mock(JweConfig::class);

        Phake::when($mockConfig)->getDecryptionKey()
            ->thenReturn(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"));

        $decryptedPayload = $jweObject->decrypt($mockConfig);

        $this->assertEquals("bar", $decryptedPayload);
    }

    public function testEncryptWithGCM()
    {
        $mockConfig = Phake::mock(JweConfig::class);

        Phake::when($mockConfig)->getEncryptionCertificate()
            ->thenReturn(file_get_contents("./resources/Certificates/test_certificate-2048.pem"));

        Phake::when($mockConfig)->getDecryptionKey()
            ->thenReturn(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"));

        Phake::when($mockConfig)->getEncryptionKeyFingerprint()
            ->thenReturn("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79");

        $jweHeader = new JweHeader("RSA-OAEP-256", "A256GCM", $mockConfig->getEncryptionKeyFingerprint(), "application/json");

        $originalPayload = "Hello world";

        $jwePayload = JweObject::encrypt($mockConfig, $originalPayload, $jweHeader);
        $jweObject = JweObject::parse($jwePayload);

        $decryptedPayload = $jweObject->decrypt($mockConfig);

        $this->assertEquals($originalPayload, $decryptedPayload);
    }

    public function testDecryptWithA128CBC_HS256Encryption()
    {
        $jweObj = JweObject::parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ");

        $decryptionKey = file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->build();

        $result = $jweObj->decrypt($config);
        $this->assertEquals("bar", $result);
    }


    public function testParse()
    {
        $jweObj = JweObject::parse("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA");
        
        $this->assertEquals(
            '{"kid":"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79","alg":"RSA-OAEP-256","enc":"A256GCM","cty":"application\/json"}',
            $jweObj->getHeader()->toJSON()
        );
    }
}
