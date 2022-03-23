<?php

namespace Mastercard\Developer\Interceptors;

use GuzzleHttp\Psr7\Response;
use Mastercard\Developer\Encryption\EncryptionException;
use Mastercard\Developer\Utils\StringUtils;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Request; // GuzzleHttp requests are implementing the PSR RequestInterface
use Mastercard\Developer\Encryption\JweConfigBuilder;
use Mastercard\Developer\Keys\DecryptionKey;
use Mastercard\Developer\Keys\EncryptionKey;

class PsrHttpMessageJweInterceptorTest extends TestCase
{

    public function testInterceptRequest_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader()
    {
        // GIVEN
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withEncryptionPath('$.foo', '$.encryptedFoo')
            ->build();

        $payload = '{"foo":"bår"}';
        $headers = ['Content-Type' => 'application/json'];
        $request = new Request('POST', 'https://api.mastercard.com/service', $headers, $payload);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $outRequest = $instanceUnderTest->interceptRequest($request);

        // THEN
        $this->assertSame($outRequest, $request);
        $encryptedPayload = $request->getBody()->__toString();
        $this->assertFalse(StringUtils::contains($encryptedPayload, 'foo'));
        $this->assertTrue(StringUtils::contains($encryptedPayload, 'encryptedFoo'));
        $this->assertEquals(1, sizeof($request->getHeader('Content-Length')));
        $this->assertEquals(strval(strlen($encryptedPayload)), $request->getHeader('Content-Length')[0]);
    }

    public function testInterceptRequest_ShouldDoNothing_WhenNoPayload()
    {
        $encryptionCerificate = EncryptionKey::load("./resources/Certificates/test_certificate-2048.pem");

        // GIVEN
        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withEncryptionCertificate($encryptionCerificate)
            ->withEncryptionPath('$.foo', '$.encryptedFoo')
            ->build();

        $request = new Request('GET', 'https://api.mastercard.com/service');
        $initialHeaderCount = sizeof($request->getHeaders());

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $outRequest = $instanceUnderTest->interceptRequest($request);

        // THEN
        $this->assertSame($outRequest, $request);
        $this->assertEmpty($request->getBody()->__toString());
        $this->assertEquals($initialHeaderCount, sizeof($request->getHeaders()));
    }

    public function testInterceptResponse_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader()
    {

        // GIVEN
        $encryptedPayload = "{" .
            "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.8c6vxeZOUBS8A9SXYUSrRnfl1ht9xxciB7TAEv84etZhQQ2civQKso-htpa2DWFBSUm-UYlxb6XtXNXZxuWu-A0WXjwi1K5ZAACc8KUoYnqPldEtC9Q2bhbQgc_qZF_GxeKrOZfuXc9oi45xfVysF_db4RZ6VkLvY2YpPeDGEMX_nLEjzqKaDz_2m0Ae_nknr0p_Nu0m5UJgMzZGR4Sk1DJWa9x-WJLEyo4w_nRDThOjHJshOHaOU6qR5rdEAZr_dwqnTHrjX9Qm9N9gflPGMaJNVa4mvpsjz6LJzjaW3nJ2yCoirbaeJyCrful6cCiwMWMaDMuiBDPKa2ovVTy0Sw.w0Nkjxl0T9HHNu4R.suRZaYu6Ui05Z3-vsw.akknMr3Dl4L0VVTGPUszcA\"}";

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->withDecryptionPath('$.encryptedPayload', '$')
            ->build();

        $headers = ['Content-Type' => 'application/json'];
        $response = new Response(200, $headers, $encryptedPayload);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $outResponse = $instanceUnderTest->interceptResponse($response);

        // THEN
        $this->assertSame($outResponse, $response);
        $payload = $response->getBody()->__toString();
        $this->assertJsonStringEqualsJsonString('{"foo":"bar"}', $payload);
        $this->assertEquals(1, sizeof($response->getHeader('Content-Length')));
        $this->assertEquals(strval(strlen($payload)), $response->getHeader('Content-Length')[0]);
    }

    public function testInterceptResponse_ShouldDecryptWithA128CBC_HS256Encryption()
    {

        // GIVEN
        $encryptedPayload = "{" .
            "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.5bsamlChk0HR3Nqg2UPJ2Fw4Y0MvC2pwWzNv84jYGkOXyqp1iwQSgETGaplIa7JyLg1ZWOqwNHEx3N7gsN4nzwAnVgz0eta6SsoQUE9YQ-5jek0COslUkoqIQjlQYJnYur7pqttDibj87fcw13G2agle5fL99j1QgFPjNPYqH88DMv481XGFa8O3VfJhW93m73KD2gvE5GasOPOkFK9wjKXc9lMGSgSArp3Awbc_oS2Cho_SbsvuEQwkhnQc2JKT3IaSWu8yK7edNGwD6OZJLhMJzWJlY30dUt2Eqe1r6kMT0IDRl7jHJnVIr2Qpe56CyeZ9V0aC5RH1mI5dYk4kHg.yI0CS3NdBrz9CCW2jwBSDw.6zr2pOSmAGdlJG0gbH53Eg.UFgf3-P9UjgMocEu7QA_vQ\"}";

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->withDecryptionPath('$.encryptedPayload', '$.foo')
            ->build();

        $headers = ['Content-Type' => 'application/json'];
        $response = new Response(200, $headers, $encryptedPayload);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $outResponse = $instanceUnderTest->interceptResponse($response);

        // THEN
        $this->assertSame($outResponse, $response);
        $payload = $response->getBody()->__toString();
        $this->assertJsonStringEqualsJsonString('{"foo":"bar"}', $payload);
        $this->assertEquals(1, sizeof($response->getHeader('Content-Length')));
        $this->assertEquals(strval(strlen($payload)), $response->getHeader('Content-Length')[0]);
    }

    public function testInterceptResponse_ShouldDoNothing_WhenNoPayload()
    {
        // GIVEN
        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->build();
        $response = new Response(200);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $outResponse = $instanceUnderTest->interceptResponse($response);

        // THEN
        $this->assertSame($outResponse, $response);
        $this->assertEmpty($response->getBody()->__toString());
        $this->assertEquals(0, sizeof($response->getHeaders()));
    }

    public function testInterceptResponse_ShouldThrowAnExceptionWhenEncryptionNotSupported()
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Encryption method A192GCM not supported');

        // GIVEN
        $encryptedPayload = "{" .
            "\"encryptedPayload\":\"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.peSgTt_lPbcNStWh-gI3yMzhOGtFCwExFwLxKeHwjzsXvHB0Fml5XnG0jRbJSfOHzKx02d0NVBzoDDRSAnafuabbbMKcoaUK-jZNHSg4BHdyBZpCO82kzvWeEm3TTNHIMBTfM00EmdFB03z_a0PaWsT-FIOzu4Sd5Z_nsNLhP9941CtVS-YtZ9WkgDezGipxA7ejQ3X5gFVy2RH1gL8OTbzIYCwBcrfSjAiCQgunNbLxPPlfZHB_6prPK7_50NS6FvuMnAhiqUiiAka8DHMdeGBWOie2Q0FV_bsRDHx_6CY8kQA3F_NXz1dELIclJhdZFfRt1y-TEfwOIj4nDi2JnA.8BYMB5MkH2ZNyFGS._xb3uDsUQcPT5fQyZw.O0MzJ5OvNyj_QMuqaloTWA\"}";

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->withDecryptionPath("$.encryptedPayload", "$.foo")
            ->build();

        $headers = ['Content-Type' => 'application/json'];
        $response = new Response(200, $headers, $encryptedPayload);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $instanceUnderTest->interceptResponse($response);
    }

    public function testInterceptResponse_ShouldThrowEncryptionException_WhenDecryptionFails()
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Invalid payload');

        // GIVEN
        $encryptedPayload = '{
            "encryptedData": "NOT-VALID"
        }';

        $decryptionKey = DecryptionKey::load("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem");

        $config = JweConfigBuilder::aJweEncryptionConfig()
            ->withDecryptionKey($decryptionKey)
            ->withDecryptionPath("$.encryptedPayload", "$.foo")
            ->build();

        $headers = ['Content-Type' => 'application/json'];
        $response = new Response(200, $headers, $encryptedPayload);

        // WHEN
        $instanceUnderTest = new PsrHttpMessageJweInterceptor($config);
        $instanceUnderTest->interceptResponse($response);
    }
}
