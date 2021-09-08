<?php

namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Encryption\JWE\JweHeader;
use PHPUnit\Framework\TestCase;

class JweHeaderTest extends TestCase
{
    public function testToJson_ShouldReturnJsonJweHeader()
    {
        $header = new JweHeader("RSA-OAEP-256", "A256GCM", "123", "application/json");
        $subjectStr = "{\"kid\":\"123\",\"cty\":\"application/json\",\"enc\":\"A256GCM\",\"alg\":\"RSA-OAEP-256\"}";
        $this->assertEquals(
            json_decode($subjectStr),
            json_decode($header->toJson())
        );
    }

    public function testParseJweHeader_ShouldCorrectlyParseJweHeader()
    {
        $header = JweHeader::parseJweHeader("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0");
        $this->assertEquals("A256GCM", $header->getEnc());
        $this->assertEquals("RSA-OAEP-256", $header->getAlg());
        $this->assertEquals("application/json", $header->getCty());
        $this->assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", $header->getKid());
    }
}
