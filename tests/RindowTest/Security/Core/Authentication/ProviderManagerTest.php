<?php
namespace RindowTest\Security\Core\Authentication\ProviderManagerTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Security\Authentication\AuthenticationProvider;
use Rindow\Security\Core\Authentication\Support\ProviderManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Security\Core\Authentication\Exception;

class TestAlwaysUnsupportsProvider implements AuthenticationProvider
{
    public function authenticate($token)
    {}
    public function supports($token)
    {
        return false;
    }
}

class TestInMemoryUserPasswordProvider implements AuthenticationProvider
{
    protected $users;
    public function __construct(array $users = null) {
        $this->users = $users;
    }
    public function authenticate($token)
    {
        if(!($token instanceof UsernamePasswordAuthenticationToken))
            throw new Exception\InvalidArgumentException('Only UsernamePasswordAuthenticationToken is supported.');

        $username = $token->getName();
        if(!isset($this->users[$username]) ||
            $this->users[$username]!==$token->getCredentials()) {
            throw new Exception\BadCredentialsException('Bad credentials');
        }
        $user = new User($username,$token->getCredentials(),array('ROLE_USER'));
        return new UsernamePasswordAuthenticationToken($user,$token->getCredentials(),array('ROLE_USER'));
    }
    public function supports($token)
    {
        if(!($token instanceof UsernamePasswordAuthenticationToken))
            return false;
        return true;
    }
}

class Test extends TestCase
{
    public function testNormalSuccess()
    {
        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager = new ProviderManager($providers);

        $token = new UsernamePasswordAuthenticationToken('foo','fooPass');
        $authenticatedToken = $providerManager->authenticate($token);
        $this->assertTrue($authenticatedToken->isAuthenticated());

        $token = new UsernamePasswordAuthenticationToken('foo','baz');
        $authenticatedToken = $providerManager->authenticate($token);
        $this->assertTrue($authenticatedToken->isAuthenticated());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testAllProvidersFaild()
    {
        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager = new ProviderManager($providers);
        $token = new UsernamePasswordAuthenticationToken('foo','boo');
        $authenticatedToken = $providerManager->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\ProviderNotFoundException
     * @expectedExceptionMessage Supported authentication provider is not found.
     */
    public function testNoProviderFound()
    {
        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager = new ProviderManager($providers);
        $token = new \stdClass();
        $authenticatedToken = $providerManager->authenticate($token);
    }

    public function testParentSuccess()
    {
        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'bar' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager1 = new ProviderManager($providers);

        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager2 = new ProviderManager($providers,$providerManager1);

        $token = new UsernamePasswordAuthenticationToken('bar','baz');
        $authenticatedToken = $providerManager2->authenticate($token);
        $this->markTestIncomplete('We need to consider proof of test success');
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testParentNoProvider()
    {
        $provider1 = new TestAlwaysUnsupportsProvider();
        $providers = array($provider1);
        $providerManager1 = new ProviderManager($providers);

        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager2 = new ProviderManager($providers,$providerManager1);

        $token = new UsernamePasswordAuthenticationToken('bar','baz');
        $authenticatedToken = $providerManager2->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\BadCredentialsException
     * @expectedExceptionMessage Bad credentials
     */
    public function testChildNoProvider()
    {
        $users = array(
            'foo' => 'fooPass',
        );
        $provider1 = new TestInMemoryUserPasswordProvider($users);
        $users = array(
            'foo' => 'baz',
        );
        $provider2 = new TestInMemoryUserPasswordProvider($users);
        $providers = array($provider1,$provider2);
        $providerManager1 = new ProviderManager($providers);

        $provider1 = new TestAlwaysUnsupportsProvider();
        $providers = array($provider1);
        $providerManager2 = new ProviderManager($providers,$providerManager1);

        $token = new UsernamePasswordAuthenticationToken('bar','baz');
        $authenticatedToken = $providerManager2->authenticate($token);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\ProviderNotFoundException
     * @expectedExceptionMessage Supported authentication provider is not found.
     */
    public function testParentAndChildNoProvider()
    {
        $provider1 = new TestAlwaysUnsupportsProvider();
        $providers = array($provider1);
        $providerManager1 = new ProviderManager($providers);

        $provider1 = new TestAlwaysUnsupportsProvider();
        $providers = array($provider1);
        $providerManager2 = new ProviderManager($providers,$providerManager1);

        $token = new UsernamePasswordAuthenticationToken('bar','baz');
        $authenticatedToken = $providerManager2->authenticate($token);
    }
}