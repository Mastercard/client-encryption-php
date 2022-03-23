<?php

namespace Mastercard\Developer\Keys;

class EncryptionKey  {
    /**
     * @var string
     */
    private $mContents;

    
    private function __construct(){
        // This class can't be instantiated
    }

    /** 
     * @param string $keyPath
     * @return EncryptionKey
     * @throws \InvalidArgumentException
    */
    public static function load($keyPath){
        $ret = new EncryptionKey();
        try {
            $ret->mContents = file_get_contents($keyPath);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Failed to read the given file: ' . $keyPath . '!', 0, $e);
        }

        return $ret;
    }

    /** 
     * @param string $contents
     * @return EncryptionKey
    */
    public static function create($contents){
        $ret = new EncryptionKey();
        $ret->mContents = $contents;
        return $ret;
    }

    /** 
     * @return string
    */
    public function getBytes(){
        return $this->mContents;
    }
}