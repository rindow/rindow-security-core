<?php
namespace RindowTest\Security\Core\Authentication\RememberMeAuthenticationTokenTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Provider\DaoAuthenticationProvider;

class Test extends TestCase
{
    public function testNewToken()
    {
    	$token = new RememberMeAuthenticationToken(sha1('key'),'name',array('ROLE_ANON'));
    	$this->assertEquals(sha1('key'),$token->getKeyHash());
    	$this->assertEquals('name',$token->getPrincipal());
    	$this->assertEquals(array('ROLE_ANON'),$token->getAuthorities());
    	$this->assertTrue($token->isAuthenticated());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage keyHash cannot be null or empty
     */
    public function testNoKey()
    {
    	$token = new RememberMeAuthenticationToken(null,'name',array('ROLE_ANON'));
    	$this->assertEquals(null,$token->getKeyHash());
    	$this->assertEquals('name',$token->getPrincipal());
    	$this->assertEquals(array('ROLE_ANON'),$token->getAuthorities());
    	$this->assertTrue($token->isAuthenticated());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage principal cannot be null or empty
     */
    public function testNoName()
    {
    	$token = new RememberMeAuthenticationToken('keyHash',null,array('ROLE_ANON'));
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage authorities cannot be null or empty
     */
    public function testNoAuthorities()
    {
    	$token = new RememberMeAuthenticationToken('keyHash','name',array());
    }

    public function testSerialize()
    {
        $token = new RememberMeAuthenticationToken('keyHash','name',array('ROLE_ANON'));
        $serialized = serialize($token);
        $token = unserialize($serialized);
        $this->assertEquals('keyHash',$token->getKeyHash());
        $this->assertEquals('name',$token->getName());
        $this->assertEquals(array('ROLE_ANON'),$token->getAuthorities());
        $this->assertTrue($token->isAuthenticated());
    }
}
