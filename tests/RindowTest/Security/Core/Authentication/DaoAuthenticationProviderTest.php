<?php
namespace RindowTest\Security\Core\Authentication\DaoAuthenticationProviderTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Crypto\PasswordEncoder\LegacyPasswordEncoder;

class Test extends TestCase
{
    public function testAuthSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);
        $cipher = new LegacyPasswordEncoder();

        $token = $provider->createToken('foo','fooPass');
        $this->assertFalse($token->isAuthenticated());

        $authenticatedToken = $provider->authenticate($token);
        $this->assertTrue($authenticatedToken->isAuthenticated());
        $this->assertEquals(array('ROLE_ADMIN'),$authenticatedToken->getAuthorities());
        $this->assertNotEquals($token,$authenticatedToken);
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\UserDetails\User',$authenticatedToken->getPrincipal());
        $this->assertEquals('foo',$authenticatedToken->getPrincipal()->getUsername());
        $this->assertEquals('foo',$authenticatedToken->getName());
    }

    public function testSupports()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','fooPass');
        $this->assertTrue($provider->supports($token));

        $token = new AnonymousAuthenticationToken('key','anonymous',array('ANONYMOUS'));
        $this->assertFalse($provider->supports($token));
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testBadPassword()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','invalidPassword');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testNullPassword()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo',null);
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testUsernameNotFoundException()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('boo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\UsernameNotFoundException
     * @expectedExceptionMessage boo
     */
    public function testUsernameNotFoundExceptionWithoutHideUserNotFoundExceptions()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);
        $provider->setHideUserNotFoundExceptions(false);

        $token = $provider->createToken('boo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\LockedException
     * @expectedExceptionMessage User account is locked
     */
    public function testAccountLocked()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
                'accountNonLocked' => false,
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\AccountExpiredException
     * @expectedExceptionMessage User account has expired
     */
    public function testAccountExpired()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
                'accountNonExpired' => false,
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\DisabledException
     * @expectedExceptionMessage User is disabled
     */
    public function testAccountDisabled()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
                'enabled' => false,
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\CredentialsExpiredException
     * @expectedExceptionMessage User credentials have expired
     */
    public function testCredentialsExpired()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
                'credentialsNonExpired' => false,
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = $provider->createToken('foo','fooPass');
        $authenticatedToken = $provider->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage Only UsernamePasswordAuthenticationToken is supported.
     */
    public function testInvalidToken()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                'roles'=>array('ADMIN'),
            ),
        );
        $userManager = new InMemoryUserDetailsManager($users);
        $provider = new DaoAuthenticationProvider($userManager);

        $token = new AnonymousAuthenticationToken('key','anonymous',array('ANONYMOUS'));
        $authenticatedToken = $provider->authenticate($token);
    }
}