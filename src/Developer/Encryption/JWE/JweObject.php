<?php

namespace Mastercard\Developer\Encryption\JWE;

use Mastercard\Developer\Encryption\JweConfig;
use Mastercard\Developer\Encryption\AES\AESCBC;
use Mastercard\Developer\Encryption\AES\AESGCM;
use Mastercard\Developer\Encryption\AES\AESEncryption;
use Mastercard\Developer\Encryption\RSA\RSA;
use Mastercard\Developer\Encryption\EncryptionException;
use Mastercard\Developer\Utils\EncodingUtils;
use phpseclib3\Crypt\AES;


class JweObject
{
    /**
     * @var JweHeader
     */
    private $header;

    /**
     * @var string
     */
    private $rawHeader;

    /**
     * @var string
     */
    private $encryptedKey;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var string
     */
    private $cipherText;

    /**
     * @var string
     */
    private $authTag;

    /**
     * @param JweHeader $rawHeader 
     * @param string $rawHeader 
     * @param string $encryptedKey
     * @param string $iv
     * @param string $cipherText
     * @param string $authTag
     */
    private function __construct($header, $rawHeader, $encryptedKey, $iv, $cipherText, $authTag)
    {
        $this->header = $header;
        $this->rawHeader = $rawHeader;
        $this->encryptedKey = $encryptedKey;
        $this->iv = $iv;
        $this->cipherText = $cipherText;
        $this->authTag = $authTag;
    }

    /**
     * @param JweConfig $config 
     * @return string 
     * @throws EncryptionException
     */
    public function decrypt($config)
    {
        $cek = RSA::unwrapSecretKey($config->getDecryptionKey()->getBytes(), EncodingUtils::base64UrlDecode($this->getEncryptedKey()));
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

    /**
     * @param JweConfig $config 
     * @param string $payload 
     * @param JweHeader $header 
     * @return string 
     * @throws EncryptionException
     */
    public static function encrypt($config, $payload, $header)
    {
        $cek = AESEncryption::generateCek(256);

        $encryptedSecretKeyBytes = RSA::wrapSecretKey($config->getEncryptionCertificate()->getBytes(), $cek);
        $encryptedKey = EncodingUtils::base64UrlEncode($encryptedSecretKeyBytes);

        $iv = AESEncryption::generateIv();

        $headerString = $header->toJSON();
        $encodedHeader = EncodingUtils::base64UrlEncode($headerString);

        $cipher = new AES('gcm');
        $cipher->setNonce($iv);
        $cipher->setKey($cek);
        $cipher->disablePadding();
        $cipher->setAAD($encodedHeader);
        $cipherText = $cipher->encrypt($payload);
        $authTag = $cipher->getTag();

        return self::serialize(
            $encodedHeader,
            $encryptedKey,
            EncodingUtils::base64UrlEncode($iv),
            EncodingUtils::base64UrlEncode($cipherText),
            EncodingUtils::base64UrlEncode($authTag)
        );
    }

    /**
     * @param string $header 
     * @param string $encryptedKey
     * @param string $iv
     * @param string $cipherText
     * @param string $authTag
     * @return string 
     */
    private static function serialize($header, $encryptedKey, $iv, $cipherText, $authTag)
    {
        return "$header.$encryptedKey.$iv.$cipherText.$authTag";
    }

    /**
     * @param string $encryptedPayload 
     * @return JweObject 
     */
    public static function parse($encryptedPayload)
    {
        $t = trim($encryptedPayload);
        
        if (substr_count($t, '.') != 4)
        {
            throw new EncryptionException("Invalid payload");
        }

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

    /**
     * @return JweObject 
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @return string
     */
    public function getRawHeader()
    {
        return $this->rawHeader;
    }

    /**
     * @return string
     */
    private function getEncryptedKey()
    {
        return $this->encryptedKey;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return string
     */
    public function getCipherText()
    {
        return $this->cipherText;
    }

    /**
     * @return string
     */
    public function getAuthTag()
    {
        return $this->authTag;
    }

    /**
     * @return string
     */
    public function toJSON()
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
