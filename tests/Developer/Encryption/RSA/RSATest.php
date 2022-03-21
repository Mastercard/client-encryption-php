<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\RSA\RSA;
use PHPUnit\Framework\TestCase;

class RSATest extends TestCase
{

    public function testWrapUnwrapSecretKey_ShouldReturnTheOriginalKey()
    {
        $originalKeyBytes = base64_decode("mZzmzoURXI3Vk0vdsPkcFw==");
        $wrappedKeyBytes = RSA::wrapSecretKey(file_get_contents("./resources/Certificates/test_certificate-2048.pem"), $originalKeyBytes);
        $decrypedKeyBytes = RSA::unwrapSecretKey(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"), $wrappedKeyBytes);

        $this->assertEquals($originalKeyBytes, $decrypedKeyBytes);
    }



    public function testUnwrapSecretKey_InteroperabilityTest_OaepSha256()
    {
        $wrappedKeyBytes = base64_decode("ZLB838BRWW2/BtdFFAWBRYShw/gBxXSwItpxEZ9zaSVEDHo7n+SyVYU7mayd+9vHkR8OdpqwpXM68t0VOrWI8LD8A2pRaYx8ICyhVFya4OeiWlde05Rhsk+TNwwREPbiw1RgjT8aedRJJYbAZdLb9XEI415Kb/UliHyvsdHMb6vKyYIjUHB/pSGAAmgds56IhIJGfvnBLPZfSHmGgiBT8WXLRuuf1v48aIadH9S0FfoyVGTaLYr+2eznSTAFC0ZBnzebM3mQI5NGQNviTnEJ0y+uZaLE/mthiKgkv1ZybyDPx2xJK2n05sNzfIWKmnI/SOb65RZLlo1Q+N868l2m9g==");
        $decrypedKeyBytes = RSA::unwrapSecretKey(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"), $wrappedKeyBytes, 'sha256');
        $expectedKeyBytes = base64_decode("mZzmzoURXI3Vk0vdsPkcFw==");

        $this->assertEquals($expectedKeyBytes, $decrypedKeyBytes);
    }

    public function testUnwrapSecretKey_InteroperabilityTest_OaepSha512()
    {
        $wrappedKeyBytes = base64_decode("RuruMYP5rG6VP5vS4kVznIrSOjUzXyOhtD7bYlVqwniWTvxxZC73UDluwDhpLwX5QJCsCe8TcwGiQRX1u+yWpBveHDRmDa03hrc3JRJALEKPyN5tnt5w7aI4dLRnLuNoXbYoTSc4V47Z3gaaK6q2rEjydx2sQ/SyVmeUJN7NgxkhtHTyVWTymEM1ythL+AaaQ5AaXedhpWKhG06XYZIX4KV7T9cHEn+See6RVGGB2RUPHBJjrxJo5JoVSfnWN0gkTMyuwbmVaTWfsowbvh8GFibFT7h3uXyI3b79NiauyB7scXp9WidGues3MrTx4dKZrSbs3uHxzPKmCDZimuKfwg==");
        $decrypedKeyBytes = RSA::unwrapSecretKey(file_get_contents("./resources/Keys/Pkcs8/test_key_pkcs8-2048.pem"), $wrappedKeyBytes, 'sha512');
        $expectedKeyBytes = base64_decode("mZzmzoURXI3Vk0vdsPkcFw==");

        $this->assertEquals($expectedKeyBytes, $decrypedKeyBytes);
    }
}
