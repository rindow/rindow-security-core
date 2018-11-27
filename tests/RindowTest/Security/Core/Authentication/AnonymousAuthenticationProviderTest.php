<?php
namespace RindowTest\Security\Core\Authentication\AnonymousAuthenticationProviderTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Provider\AnonymousAuthenticationProvider;

class Test extends TestCase
{
	public function testSuccess()
	{
		$provider = new AnonymousAuthenticationProvider('key');
		$token = $provider->createToken('name',array('ROLE_ANONYMOUS'));
		$this->assertEquals($token->getKeyHash(),$provider->getKeyHash());
		$this->assertTrue($provider->supports($token));
		$o = new \stdClass();
		$this->assertFalse($provider->supports($o));
		$token1 = $provider->authenticate($token);
		$this->assertInstanceof('Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken',$token1);
		$this->assertEquals($token,$token1);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage The presented AnonymousAuthenticationToken does not contain the expected key
     */
	public function testInvalidKeyHash()
	{
		$token = new AnonymousAuthenticationToken('BadKey','name',array('ROLE_ANONYMOUS'));
		$provider = new AnonymousAuthenticationProvider('key');
		$token1 = $provider->authenticate($token);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage Only AnonymousAuthenticationToken is supported.
     */
	public function testInvalidToken()
	{
		$token = new \stdClass();
		$provider = new AnonymousAuthenticationProvider('key');
		$token1 = $provider->authenticate($token);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage principal cannot be null or empty
     */
	public function testCreateNullPrincipal()
	{
		$provider = new AnonymousAuthenticationProvider('key');
		$token = $provider->createToken();
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage authorities cannot be null or empty
     */
	public function testCreateNullAuthorities()
	{
		$provider = new AnonymousAuthenticationProvider('key');
		$token = $provider->createToken('anonymous');
	}

	public function testCreateDefaultToken()
	{
		$provider = new AnonymousAuthenticationProvider('key','anonymous',array('ANONYMOUS'=>true));
		$token = $provider->createToken();
		$this->assertEquals('anonymous',$token->getName());
		$this->assertEquals(array('ANONYMOUS'),$token->getAuthorities());
	}
}
