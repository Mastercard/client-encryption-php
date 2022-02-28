<?php

namespace Mastercard\Developer\Encryption\JWE;

use Mastercard\Developer\Encryption\JweConfig;
use Mastercard\Developer\Encryption\AES\AESCBC;
use Mastercard\Developer\Encryption\AES\AESGCM;
use Mastercard\Developer\Encryption\RSA\RSA;
use Mastercard\Developer\Encryption\EncryptionException;
use Mastercard\Developer\Utils\EncodingUtils;


class JweObject
{
    private JweHeader $header;
    private string $rawHeader;
    private string $encryptedKey;
    private string $iv;
    private string $cipherText;
    private string $authTag;

    // private static const A128CBC_HS256 = "A128CBC-HS256";
    // private static const A256GCM = "A256GCM";

    private function __construct(JweHeader $header, string $rawHeader, string $encryptedKey, string $iv, string $cipherText, string $authTag)
    {
        $this->header = $header;
        $this->rawHeader = $rawHeader;
        $this->encryptedKey = $encryptedKey;
        $this->iv = $iv;
        $this->cipherText = $cipherText;
        $this->authTag = $authTag;
    }

    public function decrypt(JweConfig $config)
    {
        $cek = RSA::unwrapSecretKey($config->getDecryptionKey(), EncodingUtils::base64UrlDecode($this->getEncryptedKey()));
        $encryptionMethod = $this->header->getEnc();

        switch ($encryptionMethod) {
            case "A256GCM":
                return AESGCM::decrypt(
                    EncodingUtils::base64UrlDecode($this->getIv()),
                    $cek,
                    EncodingUtils::base64UrlDecode($this->getAuthTag()),
                    $this->getRawHeader(),
                    EncodingUtils::base64UrlDecode($this->getCipherText())
                );
            case "A128CBC-HS256":
                return AESCBC::decrypt(
                    EncodingUtils::base64UrlDecode($this->getIv()),
                    substr($cek, 16, 16),
                    EncodingUtils::base64UrlDecode($this->getCipherText())
                );
            default:
                throw new EncryptionException(sprintf("Encryption method %s not supported", $encryptionMethod));
        }
    }

    public static function parse(string $encryptedPayload): JweObject
    {
        $t = trim($encryptedPayload);
        $dot1 = strpos($t, '.');
        $dot2 = strpos($t, '.', $dot1 + 1);
        $dot3 = strpos($t, '.', $dot2 + 1);
        $dot4 = strpos($t, '.', $dot3 + 1);

        $header = JweHeader::parseJweHeader(substr($t, 0, $dot1));

        return new JweObject(
            $header,
            substr($t, 0, $dot1),
            substr($t, $dot1 + 1, $dot2 - $dot1 - 1),
            substr($t, $dot2 + 1, $dot3 - $dot2 - 1),
            substr($t, $dot3 + 1, $dot4 - $dot3 - 1),
            substr($t, $dot4 + 1)
        );
    }

    public function getHeader(): JweHeader
    {
        return $this->header;
    }

    public function getRawHeader(): string
    {
        return $this->rawHeader;
    }

    private function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }

    public function getIv(): string
    {
        return $this->iv;
    }

    public function getCipherText(): string
    {
        return $this->cipherText;
    }

    public function getAuthTag(): string
    {
        return $this->authTag;
    }

    public function toJSON(): string
    {
        return json_encode([
            "header" => json_decode($this->header->toJSON()),
            "encryptedKey" => $this->encryptedKey,
            "iv" => $this->iv,
            "cipherText" => $this->cipherText,
            "authTag" => $this->authTag,
        ]);
    }
}
