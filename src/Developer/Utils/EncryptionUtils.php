<?php
namespace Mastercard\Developer\Utils;

use Mastercard\Developer\Keys\EncryptionKey;
use Mastercard\Developer\Keys\DecryptionKey;
/**
 * Utility class for loading certificates and keys.
 * @package Mastercard\Developer\Utils
 */
class EncryptionUtils {
    private function __construct() {
        // This class can't be instantiated
    }

    /**
     * Create an X.509 resource from the certificate data at the given file path.
     * @param string $certificatePath
     * @return EncryptionKey
     * @throws \InvalidArgumentException
     */
    public static function loadEncryptionCertificate($certificatePath) {
        return EncryptionKey::load($certificatePath);
    }

    /**
     * Create a RSA decryption key resource from a key inside a PKCS#12 container or from an encrypted key file (PEM or DER).
     * @param string      $pkcs12KeyFileOrKeyFilePath
     * @param string|null $pkcs12DecryptionKeyAlias
     * @param string|null $pkcs12DecryptionKeyPassword
     * @return DecryptionKey
     * @throws \InvalidArgumentException
     */
    public static function loadDecryptionKey($pkcs12KeyFileOrKeyFilePath, $pkcs12DecryptionKeyAlias = null, $pkcs12DecryptionKeyPassword = null) {
        return DecryptionKey::load($pkcs12KeyFileOrKeyFilePath, $pkcs12DecryptionKeyAlias, $pkcs12DecryptionKeyPassword);
    }
}
