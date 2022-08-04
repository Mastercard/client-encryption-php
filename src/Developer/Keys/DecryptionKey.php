<?php

namespace Mastercard\Developer\Keys;

class DecryptionKey  {
    /**
     * @var string
     */
    private $mContents;

    /**
     * @var string|null
     */
    private $mAlias;

    /**
     * @var string|null
     */
    private $mPassword;

    
    private function __construct(){
        // This class can't be instantiated
    }

    /** 
     * @param string $keyPath
     * @param string $alias
     * @param string $password
     * @return DecryptionKey
     * @throws \InvalidArgumentException
    */
    public static function load($keyPath, $alias = null, $password = null){
        $ret = new DecryptionKey();
        $ret->mPath = $keyPath;
        $ret->mAlias = $alias;
        $ret->mPassword = $password;
        try {
            $pkcs12_read_results = [];

            if(openssl_pkcs12_read(file_get_contents($keyPath), $pkcs12_read_results, $password)) {
                $ret->mContents = $pkcs12_read_results['pkey'];
            }else{
                $ret->mContents = file_get_contents($keyPath); 
            }
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Failed to read the given file: ' . $keyPath . '!', 0, $e);
        }

        return $ret;
    }

    /** 
     * @return string
    */
    public function getBytes(){
        return $this->mContents;
    }

    /** 
     * @return string|null
    */
    public function getAlias(){
        return $this->mAlias;
    }
    
    /** 
     * @return string|null
    */
    public function getPassword(){
        return $this->mPassword;
    }    
}