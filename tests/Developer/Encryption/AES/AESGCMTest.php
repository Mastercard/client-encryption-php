<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\AES\AESGCM;

use PHPUnit\Framework\TestCase;

class AESGCMTest extends TestCase
{
    public function testDecrypt()
    {
        $result = AESGCM::decrypt(
            EncodingUtils::base64UrlDecode("w0Nkjxl0T9HHNu4R"),
            pack("H*", "B1EA13510FB010BC31E947301B227C49FF28BA2771766EA00A639B95A252EB3F"),
            EncodingUtils::base64UrlDecode("akknMr3Dl4L0VVTGPUszcA"),
            pack("H*", "65794A72615751694F6949334E6A46694D44417A597A466C5957526C4D3245314E446B775A5455774D44426B4D7A63344F446469595745315A545A6C597A426C4D6A4932597A41334E7A41325A5455354F5451314D575A6A4D444D79595463354969776959335235496A6F695958427762476C6A59585270623235634C32707A623234694C434A6C626D4D694F694A424D6A553252304E4E496977695957786E496A6F69556C4E424C553942525641744D6A5532496E30"),
            EncodingUtils::base64UrlDecode("suRZaYu6Ui05Z3-vsw")
        );

        $this->assertEquals("{\"foo\":\"bar\"}", $result);
    }
}
