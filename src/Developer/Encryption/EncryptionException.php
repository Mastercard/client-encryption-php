<?php

namespace Mastercard\Developer\Encryption;

use Exception;
use Throwable;

class EncryptionException extends Exception {
    /**
     * @param string                   $message
     * @param Exception|Throwable|null $previous
     */
    public function __construct($message = "", $previous = null) {
        parent::__construct($message, 0, $previous);
    }
}
