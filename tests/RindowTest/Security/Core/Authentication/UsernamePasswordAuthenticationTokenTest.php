<?php
namespace RindowTest\Security\Core\Authentication\UsernamePasswordAuthenticationTokenTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\User;

class Test extends TestCase
{
	public function testNewNoAuthToken()
	{
		$token = new UsernamePasswordAuthenticationToken('foo','foopass');
		$this->assertFalse($token->isAuthenticated());

		$this->assertEquals('foo',$token->getPrincipal());
		$this->assertEquals('foopass',$token->getCredentials());
		$this->assertEquals(array(),$token->getAuthorities());
		$this->assertEquals('foo',$token->getName());
		$this->assertNull($token->getDetails());

		$token->eraseCredentials();
		$this->assertNull($token->getCredentials());
	}

	public function testNewAuthToken()
	{
		$user = new User('foo','foopass',array('ROLE_USER'));
		$credential = new User('foo','foopass',array('ROLE_USER'));
		$token = new UsernamePasswordAuthenticationToken($user,$credential,array('ROLE_USER'));
		$this->assertTrue($token->isAuthenticated());
		$this->assertEquals($user,$token->getPrincipal());
		$this->assertEquals('foo',$token->getPrincipal()->getUsername());
		$this->assertEquals($credential,$token->getCredentials());
		$this->assertEquals('foopass',$token->getCredentials()->getPassword());
		$this->assertEquals(array('ROLE_USER'),$token->getAuthorities());
		$this->assertEquals('foo',$token->getName());
		$this->assertNull($token->getDetails());

		$details = new User('foo','foopass',array('ROLE_USER'));
		$token->setDetails($details);
		$this->assertEquals($details,$token->getDetails());

		$token->setAuthenticated(false);
		$this->assertFalse($token->isAuthenticated());

		$token->eraseCredentials();
		$this->assertNull($token->getCredentials()->getPassword());
		$this->assertNull($token->getPrincipal()->getPassword());
		$this->assertNull($token->getDetails()->getPassword());
	}

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage Cannot set this token to trusted
     */
	public function testSetAuthToEnable()
	{
		$token = new UsernamePasswordAuthenticationToken('foo','foopass');
		$this->assertFalse($token->isAuthenticated());
		$token->setAuthenticated(true);
	}

	public function testSerialize()
	{
		$user = new User('foo','foopass',array('ROLE_USER'));
		$credential = new User('boo','foopass',array('ROLE_USER'));
		$token = new UsernamePasswordAuthenticationToken($user,$credential,array('ROLE_USER'));
		$details = new User('bar','foopass',array('ROLE_USER'));
		$token->setDetails($details);

		$serialized = serialize($token);
		$token = unserialize($serialized);
		$this->assertNull($token->getPrincipal()->getPassword());
		$this->assertNull($token->getCredentials()->getPassword());
		$this->assertNull($token->getDetails()->getPassword());
		$this->assertEquals('foo',$token->getPrincipal()->getUsername());
		$this->assertEquals('boo',$token->getCredentials()->getUsername());
		$this->assertEquals('bar',$token->getDetails()->getUsername());
		$this->assertEquals(array('ROLE_USER'),$token->getAuthorities());
		$this->assertTrue($token->isAuthenticated());
	}
}