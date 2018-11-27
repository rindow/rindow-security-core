<?php
namespace Rindow\Security\Core\Authentication\Support;

use Rindow\Container\ConfigurationFactory;
use Rindow\Security\Core\Authentication\Exception;

class ProviderManagerFactory
{
    static public function factory($serviceLocator=null,$componentName=null,$args=null)
    {
        $providers = array();
        $parent = null;
        $config = ConfigurationFactory::factory($serviceLocator,$componentName,$args);
        if(isset($config['providers'])) {
            foreach ($config['providers'] as $providerName => $switch) {
                if(!$switch)
                    continue;
                $providers[] = $serviceLocator->get($providerName);
            }
        }
        if(isset($config['parent'])) {
            $parent = $serviceLocator->get($config['parent']);
        }
        return new ProviderManager($providers,$parent);
    }
}