<?php
namespace Mastercard\Developer\Utils;

class StringUtils {

    /**
     * @param string $string
     * @param string $search
     * @return bool
     */
    public static function contains($string, $search) {
        return empty($search) || strpos($string, $search) !== false;
    }

    /**
     * @param string $string
     * @param string $prefix
     * @return bool
     */
    public static function startsWith($string, $prefix) {
        return empty($prefix) || strrpos($string, $prefix, -strlen($string)) !== false;
    }

    /**
     * @param string $string
     * @param string $suffix
     * @return bool
     */
    public static function endsWith($string, $suffix) {
        if (empty($suffix)) {
            return true;
        }
        $diff = strlen($string) - strlen($suffix);
        return $diff >= 0 && strpos($string, $suffix, $diff) !== false;
    }
}
