<?php
namespace RindowTest\Security\Core\Authorization\ArrayConfigMethodSecurityTest;

use PHPUnit\Framework\TestCase;
use Rindow\Container\ModuleManager;
//use Rindow\Container\Annotations\Named;
//use Rindow\Security\Core\Authorization\Annotations\AccessControlled;
//use Rindow\Security\Core\Authorization\Annotations\RolesAllowed;
//use Rindow\Security\Core\Authorization\Annotations\DenyAll;
use Rindow\Security\Core\Authorization\Vote\AbsolutionVoter;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Aop\Support\Pointcut\Pointcut;
use Rindow\Aop\Support\Signature;
use Rindow\Aop\SignatureInterface;

/**
 * AccessControlled
 * Named
 */
class TestComponent1
{
	/**
	 * RolesAllowed({"USER"})
	 */
	public function test()
	{
		
	}
}

/**
 * AccessControlled
 * Named
 */
class TestComponent2
{
	/**
	 * RolesAllowed({"UNKNOWN"})
	 */
	public function test()
	{
		
	}
}

/**
 * AccessControlled
 * Named
 * DenyAll
 */
class TestComponent3
{
	/**
	 * RolesAllowed({"USER"})
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
                'plugins' => array(
                    //'Rindow\\Security\\Core\\Authorization\\Method\\AnnotatedComponentRegistrar'=>false,
                ),
				//'debug' => true,
				'intercept_to' => array(
					__NAMESPACE__ => true,
				),
                'pointcuts' => array(
                    __NAMESPACE__.'\TestAccess' => 'execution('.__NAMESPACE__.'\TestComponent*::*())',
                ),
				'aspects' => array(
					'Rindow\\Security\\Core\\Authorization\\DefaultArrayConfiguredMethodSecurityAdvisor'=>array(
						'advices' => array(
							'beforeAccess' => array(
		                        'pointcut_ref' => array(
		                        	__NAMESPACE__.'\TestAccess' => true,
		                        ),
							),
						),
					),
				),
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
					__NAMESPACE__.'\TestComponent1'=>array(),
					__NAMESPACE__.'\TestComponent2'=>array(),
					__NAMESPACE__.'\TestComponent3'=>array(),
                    //'Rindow\\Security\\Core\\Authorization\\DefaultDelegatingMethodSecurityMetadataSource' => array(
                    //    'factory_args' => array(
                    //        'debug' => true,
                    //        'logger' => 'Logger',
                    //    ),
                    //),
				),
			),
			'security'=> array(
                'secret' => 'THE SECRET PHRASE',
				'authorization'=>array(
					'method'=>array(
						'metadata'=>array(
							__NAMESPACE__.'\TestComponent1::test()' => array('ROLE_USER'),
							__NAMESPACE__.'\TestComponent2::test()' => array('ROLE_UNKNOWN'),
							__NAMESPACE__.'\TestComponent3::__invoke()' => array('ROLE_USER'),
						),
					),
				),
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
}
