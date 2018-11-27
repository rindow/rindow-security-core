<?php
namespace RindowTest\Security\Core\Authorization\AbstractAccessRightsBoundaryTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Security\Authentication\Authentication;
use Interop\Lenient\Security\Authentication\AuthenticationManager;
use Interop\Lenient\Security\Authorization\SecurityMetadataSource;
use Interop\Lenient\Security\Authorization\AccessDecisionManager;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authorization\Support\AbstractAccessRightsBoundary;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Stdlib\Dict;

class TestLogger
{
    public $log = array();

    public function logging($text)
    {
        $this->log[] = $text;
    }
}

class TestAuthenticationManager implements AuthenticationManager
{
    protected $authenticatedToken;
    public function __construct($authenticatedToken = null)
    {
        $this->authenticatedToken = $authenticatedToken;
    }

    public function authenticate($token)
    {
        return $this->authenticatedToken;
    }
}

class TestToken implements Authentication
{
    protected $authenticated = false;
    protected $authorities = array();
    protected $principal;

    public function __construct($principal,array $authorities = null)
    {
        $this->principal = $principal;
        if($authorities===null) {
            $this->authenticated = false;
        } else {
            $this->authenticated = true;
            $this->authorities = $authorities;
        }
    }

    public function eraseCredentials() {}

    public function getAuthorities()
    {
        return $this->authorities;
    }

    public function getCredentials() {}

    public function getPrincipal()
    {
        return $this->principal;
    }

    public function isAuthenticated()
    {
        return $this->authenticated;
    }

    public function setAuthenticated($authenticated)
    {
        $this->authenticated = $authenticated;
    }
}

class TestAccessRightsBoundary extends AbstractAccessRightsBoundary
{
    protected $logger;
    protected $runAsUser;

    public function __construct($logger,$runAsUser=null)
    {
        $this->logger = $logger;
        $this->runAsUser = $runAsUser;
    }

    protected function proceed($object)
    {
        $this->logger->logging('proceed on:'.$this->securityContext->getAuthentication()->getPrincipal());
        return $object;
    }

    public function supports(/*Object*/ $object)
    {
        if($object instanceof TestSecureObject)
            return true;
        return false;
    }

    protected function onPublicAccess($object)
    {
        $this->logger->logging('onPublicAccess');
    }

    protected function onAuthorized($object)
    {
        $this->logger->logging('onAuthorized');
    }

    protected function onAuthorizationFailure($object, $attributes, $authenticated,$accessDeniedException)
    {
        $this->logger->logging('onAuthorizationFailure');
    }

    protected function buildRunAs($authenticated, $object, $attributes)
    {
        $this->logger->logging('buildRunAs');
        return $this->runAsUser;
    }

}

class TestSecureObject
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function getPath()
    {
        return $this->path;
    }
}

class TestMetadataSource implements SecurityMetadataSource
{
    protected $attributesTable = array();

    public function __construct(array $attributesTable)
    {
        $this->attributesTable = $attributesTable;
    }

    public function getAttributes(/*Object*/ $object)
    {
        if(!array_key_exists($object->getPath(), $this->attributesTable))
            return null;
            
        return $this->attributesTable[$object->getPath()];
    }

    public function supports(/*Object*/ $object)
    {
        if($object instanceof TestSecureObject)
            return true;
        return false;
    }
}

class TestAccessDecisionManager implements AccessDecisionManager
{
    public function decide(/*Authentication*/ $authentication, /*Object*/ $object, array $attributes)
    {
        $granted = true;
        $authorities = $authentication->getAuthorities();
        foreach($attributes as $attribute) {
            if(!$this->supports($attribute))
                continue;
            $granted = false;
            foreach ($authorities as $authority) {
                if($attribute==$authority)
                    return;
            }
        }
        if(!$granted)
            throw new AccessDeniedException('Access is denied.');
    }
    public function supports(/*ConfigAttribute*/ $attribute)
    {
        if(is_string($attribute) && strpos($attribute, 'ROLE_')===0)
            return true;
        return false;
    }
}

class Test extends TestCase
{
    public function testAuthenticateAndGranted()
    {
        $config = array(
            '/path/foo' => array('ROLE_USER'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        $securityMetadataSource = new TestMetadataSource($config);
        $accessDecisionManager = new TestAccessDecisionManager();
        $boundary = new TestAccessRightsBoundary($logger);
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setSecurityMetadataSource($securityMetadataSource);
        $boundary->setAccessDecisionManager($accessDecisionManager);

        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($secureObject));
        $result = $boundary->access($secureObject);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($secureObject));
        $this->assertEquals('authenticated',$securityContext->getAuthentication()->getPrincipal());

        $result = array(
            'onAuthorized',
            'buildRunAs',
            'proceed on:authenticated',
        );
        $this->assertEquals($result,$logger->log);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
    public function testAccessDenied()
    {
        $config = array(
            '/path/foo' => array('ROLE_ADMIN'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        $accessDecisionManager = new TestAccessDecisionManager();
        $securityMetadataSource = new TestMetadataSource($config);
        $boundary = new TestAccessRightsBoundary($logger);
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setAccessDecisionManager($accessDecisionManager);
        $boundary->setSecurityMetadataSource($securityMetadataSource);

        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertEquals(array('ROLE_ADMIN'),$securityMetadataSource->getAttributes($secureObject));

        try {
            $result = $boundary->access($secureObject);
        } catch(\Exception $e) {
            $result = array(
                'onAuthorizationFailure',
            );
            $this->assertEquals($result,$logger->log);
            throw $e;
        }
    }

    public function testPublic()
    {
        $config = array(
            //'/path/foo' => array('ROLE_USER'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        $securityMetadataSource = new TestMetadataSource($config);
        $accessDecisionManager = new TestAccessDecisionManager();
        $boundary = new TestAccessRightsBoundary($logger);
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setSecurityMetadataSource($securityMetadataSource);
        $boundary->setAccessDecisionManager($accessDecisionManager);

        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertNull($securityMetadataSource->getAttributes($secureObject));
        $result = $boundary->access($secureObject);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($secureObject));
        $this->assertEquals('unauthenticated',$securityContext->getAuthentication()->getPrincipal());

        $result = array(
            'onPublicAccess',
            'proceed on:unauthenticated',
        );
        $this->assertEquals($result,$logger->log);
    }

    public function testRunAs()
    {
        $config = array(
            '/path/foo' => array('ROLE_USER'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        $securityMetadataSource = new TestMetadataSource($config);
        $accessDecisionManager = new TestAccessDecisionManager();
        $boundary = new TestAccessRightsBoundary($logger,new TestToken('another user',array('ROLE_USER')));
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setSecurityMetadataSource($securityMetadataSource);
        $boundary->setAccessDecisionManager($accessDecisionManager);

        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($secureObject));
        $result = $boundary->access($secureObject);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($secureObject));
        $this->assertEquals('authenticated',$securityContext->getAuthentication()->getPrincipal());

        $result = array(
            'onAuthorized',
            'buildRunAs',
            'proceed on:another user',
        );
        $this->assertEquals($result,$logger->log);
    }

    public function testAuthenticatedAndGranted()
    {
        $config = array(
            '/path/foo' => array('ROLE_USER'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('authenticated',array('ROLE_USER')));
        $authenticationManager = new TestAuthenticationManager(new TestToken('new-authenticate',array('ROLE_USER')));
        $securityMetadataSource = new TestMetadataSource($config);
        $accessDecisionManager = new TestAccessDecisionManager();
        $boundary = new TestAccessRightsBoundary($logger);
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setSecurityMetadataSource($securityMetadataSource);
        $boundary->setAccessDecisionManager($accessDecisionManager);

        $this->assertTrue($securityContext->getAuthentication()->isAuthenticated());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($secureObject));
        $result = $boundary->access($secureObject);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($secureObject));
        $this->assertEquals('authenticated',$securityContext->getAuthentication()->getPrincipal());

        $result = array(
            'onAuthorized',
            'buildRunAs',
            'proceed on:authenticated',
        );
        $this->assertEquals($result,$logger->log);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\AuthenticationCredentialsNotFoundException
     * @expectedExceptionMessage An Authentication object was not found in the SecurityContext
     */
    public function testCredentialsNotFound()
    {
        $config = array(
            '/path/foo' => array('ROLE_ADMIN'),
        );
        $logger = new TestLogger();
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(null);
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        $accessDecisionManager = new TestAccessDecisionManager();
        $securityMetadataSource = new TestMetadataSource($config);
        $boundary = new TestAccessRightsBoundary($logger);
        $boundary->setAuthenticationManager($authenticationManager);
        $boundary->setSecurityContext($securityContext);
        $boundary->setAccessDecisionManager($accessDecisionManager);
        $boundary->setSecurityMetadataSource($securityMetadataSource);

        $this->assertNull($securityContext->getAuthentication());
        $secureObject = new TestSecureObject('/path/foo');
        $this->assertEquals(array('ROLE_ADMIN'),$securityMetadataSource->getAttributes($secureObject));

        try {
            $result = $boundary->access($secureObject);
        } catch(\Exception $e) {
            $result = array(
            );
            $this->assertEquals($result,$logger->log);
            throw $e;
        }
    }
}
