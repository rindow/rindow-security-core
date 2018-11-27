<?php
namespace RindowTest\Security\Core\Authentication\ModuleTest;

use PHPUnit\Framework\TestCase;
use Rindow\Container\ModuleManager;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;

class Test extends TestCase
{
    public function setUp()
    {
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );
        \Rindow\Stdlib\Cache\CacheFactory::clearCache();
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );
    }

    public function getConfig()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\Security\Core\Module' => true,
                ),
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage' => 'Rindow\\Web\\Security\\Authentication\\DefaultRememberMeContextStrage',
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService' => 'Rindow\\Security\\Core\\Authentication\\DefaultInMemoryUserDetailsManager',
                ),
                'components' => array(
                    'Rindow\\Web\\Security\\Authentication\\DefaultContextStrage' => array(
                        'class' => 'Rindow\\Stdlib\\Dict',
                    ),
                ),
            ),
            'security' => array(
                'secret' => 'THE SECRET PHRASE',
                'authentication' => array(
                    'default' => array(
                        'providers' => array(
                            'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider' => true,
                            'Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider' => true,
                            'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider' => true,
                        ),
                        'users' => array(
                            'foo' => array(
                                'id' => 1,
                                // 'password' => 'fooPass',
                                'password'=>'e/5X+Q$sha256$6dE7PdnfPmRKE3COYjVemD+7olssd88SCDBqDa/qEsU=',
                                'roles'=>array('ADMIN'),
                            ),
                            'test' => array(
                                'password' => 'aaa',
                                'roles' => array('USER'),
                            ),
                        ),
                    ),
                ),
            ),
        );
        return $config;
    }

    public function testDefaultAuthenticationProviderManager()
    {
        $moduleManager = new ModuleManager($this->getConfig());
        $serviceLocator = $moduleManager->getServiceLocator();
        $authProvider = $serviceLocator->get('Rindow\\Security\\Core\\Authentication\\DefaultProviderManager');

        $usernamePassword = $serviceLocator->get('Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider')
            ->createToken('foo','fooPass');
        $this->assertFalse($usernamePassword->isAuthenticated());
        $auth = $authProvider->authenticate($usernamePassword);
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken',$auth);
        $this->assertTrue($auth->isAuthenticated());

        $anonymous = $serviceLocator->get('Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider')
            ->createToken('anonymous',array('ROLE_ANONYMOUS'));
        $auth = $authProvider->authenticate($anonymous);
        $this->assertTrue($auth->isAuthenticated());

        $rememberMe = $serviceLocator->get('Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider')
            ->createToken('var',array('ROLE_USER'));
        $auth = $authProvider->authenticate($rememberMe);
        $this->assertTrue($auth->isAuthenticated());
    }
}
