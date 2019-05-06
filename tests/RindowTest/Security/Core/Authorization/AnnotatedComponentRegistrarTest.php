<?php
namespace RindowTest\Security\Core\Authorization\AnnotatedComponentRegistrarTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Container\Annotation\Named;
use Interop\Lenient\Security\Authorization\Annotation\AccessControlled;
use Interop\Lenient\Security\Authorization\Annotation\RolesAllowed;
use Interop\Lenient\Security\Authorization\Annotation\DenyAll;
use Rindow\Container\ModuleManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Aop\Support\Pointcut\Pointcut;
use Rindow\Aop\Support\Signature;
use Rindow\Aop\SignatureInterface;

/**
 * @AccessControlled
 * @Named
 */
class TestComponent1
{
	/**
	 * @RolesAllowed({"USER"})
	 */
	public function test()
	{
		
	}
}

/**
 * @AccessControlled
 * @Named
 */
class TestComponent2
{
	/**
	 * @RolesAllowed({"UNKNOWN"})
	 */
	public function test()
	{
		
	}
}

/**
 * @AccessControlled
 * @Named
 * @DenyAll
 */
class TestComponent3
{
	/**
	 * @RolesAllowed({"USER"})
	 */
	public function __invoke()
	{
		
	}
}

class Test extends TestCase
{
    public function setUp()
    {
    }

    public function getConfig()
    {
		$config = array(
			'module_manager' => array(
				'modules' => array(
					'Rindow\\Aop\\Module' => true,
					'Rindow\\Container\\Module' => true,
					'Rindow\\Security\\Core\\Module' => true,
					//'Rindow\\Module\\Monolog\\Module' => true,
				),
				'annotation_manager' => true,
				'enableCache'=>false,
			),
			'aop' => array(
				//'debug' => true,
				//'intercept_to' => array(
				//	__NAMESPACE__ => true,
				//),
			),
			'container' => array(
				//'debug' => true,
				'component_paths' => array(
					__DIR__ => true,
				),
				'aliases' => array(
					'Rindow\Security\Core\Authentication\DefaultContextStrage' => __NAMESPACE__.'\TestContextStrage',
				),
				'components' => array(
					__NAMESPACE__.'\TestContextStrage' => array(
						'class' => 'Rindow\Stdlib\Dict',
					),
				),
			),
            'security' => array(
                'secret' => 'THE SECRET PHRASE',
                'authentication' => array(
                    'default' => array(
                        'providers' => array(
                            'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider'=>true,
                        ),
                    ),
                ),
            ),
		);
		return $config;
    }

	public function testBuildAdvice()
	{
		$config = array(
			'module_manager' => array(
				'modules' => array(
					'Rindow\\Aop\\Module' => true,
					'Rindow\\Container\\Module' => true,
					'Rindow\\Security\\Core\\Module' => true,
					//'Rindow\\Module\\Monolog\\Module' => true,
				),
				'annotation_manager' => true,
				'enableCache'=>false,
			),
			'aop' => array(
				//'debug' => true,
			),
			'container' => array(
				'component_paths' => array(
					__DIR__ => true,
				),
			),
            'security' => array(
                'secret' => 'THE SECRET PHRASE',
			),
		);
		$moduleManager = new ModuleManager($config);
		$config = $moduleManager->getConfig();
		$serviceLocator = $moduleManager->getServiceLocator();
		$aopManager = $serviceLocator->getProxyManager();
		$adviceManager = $aopManager->getAdviceManager();
		$pointcutManager = $adviceManager->getPointcutManager();

		$pointcuts = array_values($pointcutManager->getPointcuts());
		// ** CAUTION $pointcuts includes pointcuts of the Dao and the Transacion **
		$this->assertCount(2,$pointcuts);
		$this->assertEquals('execution('.__NAMESPACE__.'\TestComponent1::*())||'.
							'execution('.__NAMESPACE__.'\TestComponent2::*())||'.
							'execution('.__NAMESPACE__.'\TestComponent3::*())',
							$pointcuts[1]->value);

		$advices = $adviceManager->getAdvices($pointcuts[1]);
		$this->assertCount(1,$advices);
		$this->assertInstanceOf('Rindow\Aop\Support\Advice\AdviceDefinition',$advices[0]);
		$pointcutRefs = $advices[0]->getPointcutSignatures();
		$this->assertEquals('Rindow\Security\Core\Authorization\DefaultAnnotatedMethodSecurityAdvisor::beforeAccess()',$pointcutRefs[0]);
		$this->assertEquals('before',$advices[0]->getType());
		$this->assertEquals('Rindow\Security\Core\Authorization\DefaultMethodSecurityAdvisor',$advices[0]->getComponentName());
		$this->assertEquals('beforeAccess',$advices[0]->getMethod());
	}

	public function testAllowAccess()
	{
		$moduleManager = new ModuleManager($this->getConfig());
		$serviceLocator = $moduleManager->getServiceLocator();
		$auth = new UsernamePasswordAuthenticationToken(
			'testuser','testuser',array('ROLE_USER'));
		$serviceLocator->get(__NAMESPACE__.'\TestContextStrage')->
			set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
		$component1 = $serviceLocator->get(__NAMESPACE__.'\TestComponent1');
		$component1->test();
		$this->assertTrue(true);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
	public function testAccessDenied()
	{
		$moduleManager = new ModuleManager($this->getConfig());
		$serviceLocator = $moduleManager->getServiceLocator();
		$auth = new UsernamePasswordAuthenticationToken(
			'testuser','testuser',array('ROLE_ADMIN'));
		$serviceLocator->get(__NAMESPACE__.'\TestContextStrage')->
			set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
		$component1 = $serviceLocator->get(__NAMESPACE__.'\TestComponent1');
		$component1->test();
	}

	public function testAllowInvokeMethod()
	{
		$moduleManager = new ModuleManager($this->getConfig());
		$serviceLocator = $moduleManager->getServiceLocator();
		$auth = new UsernamePasswordAuthenticationToken(
			'testuser','testuser',array('ROLE_USER'));
		$serviceLocator->get(__NAMESPACE__.'\TestContextStrage')->
			set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
		$component3 = $serviceLocator->get(__NAMESPACE__.'\TestComponent3');
		call_user_func($component3);
		$this->assertTrue(true);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
	public function testDenyInvokeMethod()
	{
		$moduleManager = new ModuleManager($this->getConfig());
		$serviceLocator = $moduleManager->getServiceLocator();
		$auth = new UsernamePasswordAuthenticationToken(
			'testuser','testuser',array('ROLE_OTHER'));
		$serviceLocator->get(__NAMESPACE__.'\TestContextStrage')->
			set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
		$component3 = $serviceLocator->get(__NAMESPACE__.'\TestComponent3');
		call_user_func($component3);
		$this->assertTrue(true);
	}

	public function testNoAccessControlledClasses()
	{
		$config = array(
			'container' => array(
				//'debug' => true,
				'component_paths' => array(
					__DIR__ => false,
				),
				'components' => array(
					__NAMESPACE__.'\TestComponent1' => array(),
				),
			),
		);
		$config = array_replace_recursive($this->getConfig(), $config);

		$moduleManager = new ModuleManager($config);
		$serviceLocator = $moduleManager->getServiceLocator();
		$auth = new UsernamePasswordAuthenticationToken(
			'testuser','testuser',array('ROLE_USER'));
		$serviceLocator->get(__NAMESPACE__.'\TestContextStrage')->
			set('Rindow.Security.Authentication.DefaultSecurityContext.Authentication',$auth);
		$component1 = $serviceLocator->get(__NAMESPACE__.'\TestComponent1');
		$component1->test();
		$this->assertTrue(true);
	}
}
