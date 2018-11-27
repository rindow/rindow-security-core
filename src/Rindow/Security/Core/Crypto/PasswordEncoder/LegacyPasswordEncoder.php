<?php
namespace Rindow\Security\Core\Crypto\PasswordEncoder;

use Interop\Lenient\Security\Crypto\PasswordEncoder\PasswordEncoder;

class LegacyPasswordEncoder implements PasswordEncoder
{
    public function encode($password,$salt=null,$algorithm=null)
    {
        if($salt==null) {
            $rand=substr('00000000'.dechex(mt_rand()),-8);
            $salt=str_replace('=','',base64_encode($this->hex2bin($rand)));
        }
        if($algorithm==null)
            $algorithm = 'sha256';
        $hash=$this->doSign($algorithm,$salt,$password);
        $output = base64_encode($this->hex2bin($hash));
        return $salt.'$'.$algorithm.'$'.$output;
    }

    public function hex2bin($hex)
    {
        if(version_compare(PHP_VERSION, '5.4.0')>=0)
            return hex2bin($hex);
        $len = strlen($hex);
        $bin = '';
        for ($pos=0; $pos < $len; $pos+=2) { 
            $bin .= chr(hexdec(substr($hex, $pos, 2)));
        }
        return $bin;
    }

    protected function doSign($algorithm,$salt,$password)
    {
        return hash_hmac($algorithm,$salt,$password);
    }

    public function isPasswordValid($encodedPassword,$presentedPassword)
    {
        $parts = explode('$',$encodedPassword);
        $salt = $algorithm = null;
        if(count($parts)==3) {
            $salt = $parts[0];
            $algorithm = $parts[1];
        }
        $presentedPassword = $this->encode($presentedPassword,$salt,$algorithm);
        if($encodedPassword===$presentedPassword)
            return true;
        return false;
    }
}