<?php
namespace RindowTest\Security\Core\Crypto\LegacyPasswordEncoderTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Crypto\PasswordEncoder\LegacyPasswordEncoder;

class Test extends TestCase
{
    protected function hex2bin($hex)
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

	public function testCreateEncodedPassword()
	{
		$encoder = new LegacyPasswordEncoder();
		$password = 'boo';
		$encodedPassword = $encoder->encode($password);
		$parts = explode('$',$encodedPassword);
		$salt = $parts[0];
		$p = $salt.'$'.'sha256'.'$'.base64_encode($this->hex2bin(hash_hmac('sha256',$salt,$password)));
		$this->assertNotEmpty($salt);
		$this->assertEquals($p,$encodedPassword);

		$encodedPassword = $encoder->encode($password);
		$parts = explode('$',$encodedPassword);
		$salt2 = $parts[0];
		$this->assertNotEquals($salt,$salt2);
	}

	public function testValidatePassword()
	{
		$encoder = new LegacyPasswordEncoder();
		$password = 'boo';
		$encodedPassword1 = $encoder->encode('boo');
		$encodedPassword2 = $encoder->encode('boo');
		$encodedPassword3 = $encoder->encode('foo');

		$this->assertNotEquals($encodedPassword1,$encodedPassword2);
		$this->assertNotEquals($encodedPassword2,$encodedPassword3);

		$this->assertTrue( $encoder->isPasswordValid($encodedPassword1,'boo'));
		$this->assertTrue( $encoder->isPasswordValid($encodedPassword2,'boo'));
		$this->assertFalse($encoder->isPasswordValid($encodedPassword3,'boo'));
	}

	public function testHex2bin()
	{
		$encoder = new LegacyPasswordEncoder();
		$this->assertEquals('ABC',$encoder->hex2bin('414243'));
	}
}