<?php
namespace RindowTest\Security\Core\Authentication\RememberMeAuthenticationProviderTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Provider\RememberMeAuthenticationProvider;

class Test extends TestCase
{
	public function testSuccess()
	{
		$provider = new RememberMeAuthenticationProvider('key');
		$token = $provider->createToken('name',array('ANON'));
		$this->assertEquals($token->getKeyHash(),$provider->getKeyHash());
		$this->assertTrue($provider->supports($token));
		$o = new \stdClass();
		$this->assertFalse($provider->supports($o));
		$token1 = $provider->authenticate($token);
		$this->assertInstanceof('Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken',$token1);
		$this->assertEquals($token,$token1);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage The presented RememberMeAuthenticationToken does not contain the expected key
     */
	public function testFail()
	{
		$token = new RememberMeAuthenticationToken(sha1('BadKey'),'name',array('ANON'));
		$provider = new RememberMeAuthenticationProvider('key');
		$token1 = $provider->authenticate($token);
	}


    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage Only RememberMeAuthenticationToken is supported.
     */
	public function testInvalidToken()
	{
		$token = new \stdClass();
		$provider = new RememberMeAuthenticationProvider('key');
		$token1 = $provider->authenticate($token);
	}
}
