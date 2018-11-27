<?php
namespace RindowTest\Security\Core\Authorization\MethodSecurityAdvisorTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Security\Authentication\Authentication;
use Interop\Lenient\Security\Authentication\AuthenticationManager;
use Interop\Lenient\Security\Authorization\AccessDecisionManager;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;

use Rindow\Security\Core\Authorization\Vote\RoleVoter;
use Rindow\Security\Core\Authorization\Vote\AbsolutionVoter;
use Rindow\Security\Core\Authorization\Vote\AuthenticatedVoter;
use Rindow\Security\Core\Authorization\Vote\UnanimousBased;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Stdlib\Dict;
use Rindow\Annotation\AnnotationManager;
use Rindow\Security\Core\Module;
use Rindow\Security\Core\Authorization\Method\MethodSecurityAdvisor;
use Rindow\Security\Core\Authorization\Method\DelegatingMethodSecurityMetadataSource;
use Rindow\Security\Core\Authorization\Method\AnnotationMethodSecurityMetadataSource;
use Rindow\Aop\ProceedingJoinPointInterface;
use Rindow\Aop\Support\Signature;
use Rindow\Aop\SignatureInterface;

use Rindow\Security\Core\Authorization\Annotation\RolesAllowed;
use Rindow\Security\Core\Authorization\Annotation\PermitAll;
use Rindow\Security\Core\Authorization\Annotation\DenyAll;
use Rindow\Security\Core\Authorization\Annotation\Authenticated;
use Rindow\Security\Core\Authorization\Annotation\FullyAuthenticated;

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

class TestInvocation implements ProceedingJoinPointInterface
{
	protected $target;
    protected $signature;

	public function __construct($target,$signature)
	{
		$this->target = $target;
        $this->signature = $signature;
	}
    public function proceed(array $args=null)
    {
        return $this->target;
    }
    public function getTarget()
    {
        return $this->target;
    }
    public function getParameters(){}
    public function getAction(){}
    public function getSignature()
    {
        return $this->signature;
    }
    public function getSignatureString()
    {
    	return $this->signature->toString();
    }
    public function toString(){}
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

class TestTargetAllowedByMethod
{
    /**
     * @RolesAllowed({user})
     */
    public function method1()
    {
    	return 'result1';
    }
    public function method2()
    {
    }
    /**
     * @DenyAll
     */
    public function method3()
    {
    }
}

class TestTargetAuthenticatedByMethod
{
    /**
     * @RolesAllowed({user})
     * @Authenticated
     */
    public function method1()
    {
        return 'result1';
    }
    /**
     * @RolesAllowed({user})
     * @FullyAuthenticated
     */
    public function method2()
    {
    }
}

class Test extends TestCase
{
    public function setUp()
    {
        \Rindow\Stdlib\Cache\CacheFactory::clearCache();
    }

    public function getAnnotationManager()
    {
        $annotationManager = new AnnotationManager();
        $module = new Module();
        $config = $module->getConfig();
        $annotationManager->setAliases($config['annotation']['aliases']);
        return $annotationManager;
    }

    public function testAuthenticateAndGranted()
    {
        $logger = new TestLogger();
        // AuthenticationManager
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        // Metadata
        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
    	$metadata = new AnnotationMethodSecurityMetadataSource();
    	$metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);
        $methodSecurityMetadataSources = array($metadata);
        $securityMetadataSource = new DelegatingMethodSecurityMetadataSource($methodSecurityMetadataSources);
        // DecisionManager
		$voters = array(
			new AbsolutionVoter(),
			$roleVoter,
		);
		$accessDecisionManager = new UnanimousBased($voters);
        // AuthenticationTrustResolver
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        // MethodSecurityAdvisor
        $advisor = new MethodSecurityAdvisor();
        $advisor->setAuthenticationManager($authenticationManager);
        $advisor->setSecurityContext($securityContext);
        $advisor->setSecurityMetadataSource($securityMetadataSource);
        $advisor->setAccessDecisionManager($accessDecisionManager);
        $advisor->setAuthenticationTrustResolver($authenticationTrustResolver);

        // Do Test
        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $target = new TestTargetAllowedByMethod();
        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);

        //$this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($invocation));
        $result = $advisor->access($invocation);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($target));
        $this->assertEquals('authenticated',$securityContext->getAuthentication()->getPrincipal());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
    public function testAccessDenied()
    {
        $logger = new TestLogger();
        // AuthenticationManager
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new TestToken('unauthenticated'));
        $authenticationManager = new TestAuthenticationManager(new TestToken('authenticated',array('ROLE_USER')));
        // Metadata
        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
    	$metadata = new AnnotationMethodSecurityMetadataSource();
    	$metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);
        $methodSecurityMetadataSources = array($metadata);
        $securityMetadataSource = new DelegatingMethodSecurityMetadataSource($methodSecurityMetadataSources);
        // DecisionManager
		$voters = array(
			new AbsolutionVoter(),
			$roleVoter,
		);
		$accessDecisionManager = new UnanimousBased($voters);
        // AuthenticationTrustResolver
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        // MethodSecurityAdvisor
        $advisor = new MethodSecurityAdvisor();
        $advisor->setAuthenticationManager($authenticationManager);
        $advisor->setSecurityContext($securityContext);
        $advisor->setSecurityMetadataSource($securityMetadataSource);
        $advisor->setAccessDecisionManager($accessDecisionManager);
        $advisor->setAuthenticationTrustResolver($authenticationTrustResolver);

        // Do Test
        $this->assertFalse($securityContext->getAuthentication()->isAuthenticated());
        $target = new TestTargetAllowedByMethod();
        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method3');
        $invocation = new TestInvocation($target,$signature);

        //$this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($invocation));
        $result = $advisor->access($invocation);
        $this->assertEquals(spl_object_hash($result),spl_object_hash($target));
        $this->assertEquals('authenticated',$securityContext->getAuthentication()->getPrincipal());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AuthenticationRequiredException
     * @expectedExceptionMessage Authentication required.
     */
    public function testAuthenticationRequiredException()
    {
        $logger = new TestLogger();
        // AuthenticationManager
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new AnonymousAuthenticationToken('key','unauthenticated',array('IS_AUTHENTICATED_ANONYMOUSLY')));
        $authenticationManager = new TestAuthenticationManager(new AnonymousAuthenticationToken('key','unauthenticated',array('IS_AUTHENTICATED_ANONYMOUSLY')));
        // Metadata
        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);
        $methodSecurityMetadataSources = array($metadata);
        $securityMetadataSource = new DelegatingMethodSecurityMetadataSource($methodSecurityMetadataSources);
        // DecisionManager
        $voters = array(
            new AbsolutionVoter(),
            new AuthenticatedVoter(),
            $roleVoter,
        );
        $accessDecisionManager = new UnanimousBased($voters);
        // AuthenticationTrustResolver
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        // MethodSecurityAdvisor
        $advisor = new MethodSecurityAdvisor();
        $advisor->setAuthenticationManager($authenticationManager);
        $advisor->setSecurityContext($securityContext);
        $advisor->setSecurityMetadataSource($securityMetadataSource);
        $advisor->setAccessDecisionManager($accessDecisionManager);
        $advisor->setAuthenticationTrustResolver($authenticationTrustResolver);

        // Do Test
        $target = new TestTargetAuthenticatedByMethod();
        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);

        //$this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($invocation));
        $result = $advisor->access($invocation);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\FullAuthenticationRequiredException
     * @expectedExceptionMessage Full authentication required.
     */
    public function testFullyAuthenticationRequiredException()
    {
        $logger = new TestLogger();
        // AuthenticationManager
        $securityContext = new SecurityContext(new Dict(),'test');
        $securityContext->setAuthentication(new RememberMeAuthenticationToken('key','unauthenticated',array('IS_AUTHENTICATED_REMEMBERED')));
        $authenticationManager = new TestAuthenticationManager(new RememberMeAuthenticationToken('key','authenticated',array('ROLE_USER','IS_AUTHENTICATED_REMEMBERED')));
        // Metadata
        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);
        $methodSecurityMetadataSources = array($metadata);
        $securityMetadataSource = new DelegatingMethodSecurityMetadataSource($methodSecurityMetadataSources);
        // DecisionManager
        $voters = array(
            new AbsolutionVoter(),
            new AuthenticatedVoter(),
            $roleVoter,
        );
        $accessDecisionManager = new UnanimousBased($voters);
        // AuthenticationTrustResolver
        $authenticationTrustResolver = new AuthenticationTrustResolver();
        // MethodSecurityAdvisor
        $advisor = new MethodSecurityAdvisor();
        $advisor->setAuthenticationManager($authenticationManager);
        $advisor->setSecurityContext($securityContext);
        $advisor->setSecurityMetadataSource($securityMetadataSource);
        $advisor->setAccessDecisionManager($accessDecisionManager);
        $advisor->setAuthenticationTrustResolver($authenticationTrustResolver);

        // Do Test
        $target = new TestTargetAuthenticatedByMethod();
        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);

        //$this->assertEquals(array('ROLE_USER'),$securityMetadataSource->getAttributes($invocation));
        $result = $advisor->access($invocation);
    }
}
