<?php

namespace Mastercard\Developer\Encryption\JWE;

class JweHeader
{
    private $enc;
    private $kid;
    private $alg;
    private $cty;

    public function __construct($alg, $enc, $kid, $cty)
    {
        $this->alg = $alg;
        $this->enc = $enc;
        $this->kid = $kid;
        $this->cty = $cty;
    }

    public function toJson()
    {
        $obj = [];

        if (isset($this->kid)) $obj["kid"] = $this->kid;
        if (isset($this->alg)) $obj["alg"] = $this->alg;
        if (isset($this->enc)) $obj["enc"] = $this->enc;
        if (isset($this->cty)) $obj["cty"] = $this->cty;

        return json_encode($obj);
    }

    public static function parseJweHeader($encodedHeader)
    {

        $headerObj = json_decode(base64_decode($encodedHeader), true);

        $alg = $headerObj["alg"];
        $enc = $headerObj["enc"];
        $kid = $headerObj["kid"];
        $cty = $headerObj["cty"];

        return new JweHeader($alg, $enc, $kid, $cty);
    }

    public function getEnc()
    {
        return $this->enc;
    }
    public function getAlg()
    {
        return $this->alg;
    }
    public function getKid()
    {
        return $this->kid;
    }
    public function getCty()
    {
        return $this->cty;
    }
}
