<?php
namespace RindowTest\Security\Core\Authorization\AnnotationMethodSecurityMetadataSourceTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Security\Authorization\Annotation\RolesAllowed;
use Interop\Lenient\Security\Authorization\Annotation\PermitAll;
use Interop\Lenient\Security\Authorization\Annotation\DenyAll;
use Interop\Lenient\Security\Authorization\Annotation\Authenticated;
use Interop\Lenient\Security\Authorization\Annotation\FullyAuthenticated;

use Rindow\Security\Core\Authorization\Method\AnnotationMethodSecurityMetadataSource;
use Rindow\Security\Core\Authorization\Vote\RoleVoter;
use Rindow\Security\Core\Authorization\Vote\AbsolutionVoter;
use Rindow\Aop\ProceedingJoinPointInterface;
use Rindow\Aop\Support\Signature;
use Rindow\Aop\SignatureInterface;
use Rindow\Annotation\AnnotationManager;
use Rindow\Security\Core\Module;

class TestTargetAllowedByMethod
{
    /**
     * @RolesAllowed({user})
     */
    public function method1()
    {
    }
    public function method2()
    {
    }
}

/**
 * @RolesAllowed({user})
 */
class TestTargetAllowedByClass
{
    /**
     * @RolesAllowed({admin})
     */
    public function method1()
    {
    }
    public function method2()
    {
    }
}

/**
 * @RolesAllowed({user})
 */
class TestTargetPermitAllByMethod
{
    /**
     * @PermitAll
     */
    public function method1()
    {
    }

    public function method2()
    {
    }
}

/**
 * @PermitAll
 */
class TestTargetPermitAllByClass
{
    /**
     * @RolesAllowed({user})
     */
    public function method1()
    {
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

/**
 * @RolesAllowed({user})
 */
class TestTargetDenyAllByMethod
{
    /**
     * @DenyAll
     */
    public function method1()
    {
    }

    public function method2()
    {
    }
}

/**
 * @DenyAll
 */
class TestTargetDenyAllByClass
{
    /**
     * @RolesAllowed({user})
     */
    public function method1()
    {
    }
    public function method2()
    {
    }
    /**
     * @PermitAll
     */
    public function method3()
    {
    }
}

/**
 * @DenyAll
 * @RolesAllowed({user})
 */
class TestMultualAnnotationByClass
{
    /**
     * @RolesAllowed({user})
     */
    public function method1()
    {
    }
    public function method2()
    {
    }
}

/**
 * @RolesAllowed({user})
 */
class TestMultualAnnotationByMethod
{
    /**
     * @RolesAllowed({user})
     * @DenyAll
     */
    public function method1()
    {
    }
    public function method2()
    {
    }
}

/**
 * @Authenticated
 */
class TestTargetAuthenticated
{
    /**
     * @FullyAuthenticated
     */
    public function method1()
    {
    }
    public function method2()
    {
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
    public function proceed(array $args=null){}
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
    	return $this->signatureString;
    }
    public function toString(){}
}

class Test extends TestCase
{
    public function getAnnotationManager()
    {
        $annotationManager = new AnnotationManager();
        $module = new Module();
        $config = $module->getConfig();
        $annotationManager->setAliases($config['annotation']['aliases']);
        return $annotationManager;
    }

    public function testAllowedByMethod()
    {
        $annotationManager = $this->getAnnotationManager();
        $target = new TestTargetAllowedByMethod();

        $roleVoter = new RoleVoter();
    	$metadata = new AnnotationMethodSecurityMetadataSource();
    	$metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
    	$invocation = new TestInvocation($target,$signature);
    	$this->assertTrue($metadata->supports($invocation));
    	$this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
    	$this->assertTrue($metadata->supports($invocation));
        $this->assertNull($metadata->getAttributes($invocation));

    	$dummy = new \stdClass();
    	$this->assertFalse($metadata->supports($dummy));
    	$this->assertFalse($metadata->supports(array()));
    }

    public function testAllowedByClass()
    {
        $target = new TestTargetAllowedByClass();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER','ROLE_ADMIN'),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }

    public function testPermitAllByMethod()
    {
        $target = new TestTargetPermitAllByMethod();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::PERMIT_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }

    public function testPermitAllByClass()
    {
        $target = new TestTargetPermitAllByClass();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::PERMIT_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method3');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::DENY_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }

    public function testDenyAllByMethod()
    {
        $target = new TestTargetDenyAllByMethod();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::DENY_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }

    public function testDenyAllByClass()
    {
        $target = new TestTargetDenyAllByClass();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::DENY_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method3');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array(AbsolutionVoter::PERMIT_ALL_ATTRIBUTE),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\DomainException
     * @expectedExceptionMessage @RolesAllowed is invalid. DenyAll and PermitAll annotations must be used exclusively with other annotations
     */
    public function testMultualAnnotationByClass()
    {
        $target = new TestMultualAnnotationByClass();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $metadata->getAttributes($invocation);
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\DomainException
     * @expectedExceptionMessage @DenyAll is invalid. DenyAll and PermitAll annotations must be used exclusively with other annotations
     */
    public function testMultualAnnotationByMethod()
    {
        $target = new TestMultualAnnotationByMethod();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $metadata->getAttributes($invocation);
    }

    public function testAuthenticated()
    {
        $target = new TestTargetAuthenticated();

        $annotationManager = $this->getAnnotationManager();
        $roleVoter = new RoleVoter();
        $metadata = new AnnotationMethodSecurityMetadataSource();
        $metadata->setAnnotationReader($annotationManager);
        $metadata->setRoleVoter($roleVoter);

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method1');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('IS_AUTHENTICATED_REMEMBERED','IS_AUTHENTICATED_FULLY'),$metadata->getAttributes($invocation));

        $signature = new Signature(SignatureInterface::TYPE_METHOD,get_class($target),'method2');
        $invocation = new TestInvocation($target,$signature);
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('IS_AUTHENTICATED_REMEMBERED'),$metadata->getAttributes($invocation));

        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }
}
