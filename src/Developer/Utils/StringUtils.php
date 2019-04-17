<?php
namespace Mastercard\Developer\Utils;

class StringUtils {

    public static function startsWith($string, $prefix) {
        return empty($prefix) || strrpos($string, $prefix, -strlen($string)) !== false;
    }

    public static function endsWith($string, $suffix) {
        if (empty($suffix)) {
            return true;
        }
        $diff = strlen($string) - strlen($suffix);
        return $diff >= 0 && strpos($string, $suffix, $diff) !== false;
    }
}