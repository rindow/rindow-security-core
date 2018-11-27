<?php
namespace RindowTest\Security\Core\Authentication\AnonymousAuthenticationTokenTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;


class Test extends TestCase
{
    public function testNewToken()
    {
    	$token = new AnonymousAuthenticationToken('keyHash','name',array('ROLE_ANON'));
    	$this->assertEquals('keyHash',$token->getKeyHash());
    	$this->assertEquals('name',$token->getPrincipal());
    	$this->assertEquals(array('ROLE_ANON'),$token->getAuthorities());
    	$this->assertTrue($token->isAuthenticated());
    }

    public function testNoKey()
    {
    	$token = new AnonymousAuthenticationToken(null,'name',array('ROLE_ANON'));
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
    	$token = new AnonymousAuthenticationToken('keyHash',null,array('ROLE_ANON'));
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage authorities cannot be null or empty
     */
    public function testNoAuthorities()
    {
    	$token = new AnonymousAuthenticationToken('keyHash','name',array());
    }

    public function testSerialize()
    {
        $token = new AnonymousAuthenticationToken('keyHash','name',array('ROLE_ANON'));
        $serialized = serialize($token);
        $token = unserialize($serialized);
        $this->assertEquals('keyHash',$token->getKeyHash());
        $this->assertEquals('name',$token->getName());
        $this->assertEquals(array('ROLE_ANON'),$token->getAuthorities());
        $this->assertTrue($token->isAuthenticated());
    }
}
