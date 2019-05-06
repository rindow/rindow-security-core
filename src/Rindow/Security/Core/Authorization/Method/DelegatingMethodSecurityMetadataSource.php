<?php
namespace Rindow\Security\Core\Authorization\Method;

use Rindow\Stdlib\Cache\ConfigCache\ConfigCacheFactory;

class DelegatingMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource
{
    const NULL_MARK = '$$$$NULL$$$$';
    protected $methodSecurityMetadataSources = array();
    protected $cache;
    protected $configCacheFactory;
    protected $debug;
    protected $logger;

    static public function factory($serviceLocator,$componentName,$args)
    {
        $methodSecurityMetadataSources = array();
        $configCacheFactory = null;
        if(isset($args['sources'])) {
            foreach($args['sources'] as $name) {
                $methodSecurityMetadataSources[] = $serviceLocator->get($name);
            }
        }
        if(isset($args['configCacheFactory'])) {
            $configCacheFactory = $serviceLocator->get($args['configCacheFactory']);
        }
        $instance = new self($methodSecurityMetadataSources,$configCacheFactory);
        if(isset($args['debug'])) {
            $instance->setDebug($args['debug']);
        }
        if(isset($args['logger'])) {
            $logger = $serviceLocator->get($args['logger']);
            $instance->setLogger($logger);
        }
        return $instance;
    }

    public function __construct(array $methodSecurityMetadataSources=null,$configCacheFactory=null)
    {
        if($methodSecurityMetadataSources)
            $this->setMethodSecurityMetadataSources($methodSecurityMetadataSources);
        if($configCacheFactory)
            $this->setConfigCacheFactory($configCacheFactory);
    }

    public function setDebug($debug)
    {
        $this->debug = $debug;
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    public function setMethodSecurityMetadataSources(array $methodSecurityMetadataSources=null)
    {
        $this->methodSecurityMetadataSources = $methodSecurityMetadataSources;
    }

    public function setConfigCacheFactory($configCacheFactory)
    {
        $this->configCacheFactory = $configCacheFactory;
    }

    protected function getCache()
    {
        if($this->cache)
            return $this->cache;
        if($this->configCacheFactory==null)
            $this->configCacheFactory = new ConfigCacheFactory(array('enableCache'=>false));
        $this->cache = $this->configCacheFactory->create(__CLASS__.'/attr');
        return $this->cache;
    }

    public function getAttributes($invocation)
    {
        $signatureString = $invocation->getSignatureString();
        $this->logDebug('Get attributes at :'.$signatureString);
        $cache = $this->getCache();
        $attributes = $cache->getEx($signatureString,
            function ($cacheKey,$args) {
                list($invocation,$methodSecurityMetadataSources) = $args;
                foreach($methodSecurityMetadataSources as $methodSecurityMetadataSource) {
                    $attributes = $methodSecurityMetadataSource->getAttributes($invocation);
                    if($attributes===null)
                        continue;
                    return $attributes;
                }
                return DelegatingMethodSecurityMetadataSource::NULL_MARK;
            },
            array($invocation,$this->methodSecurityMetadataSources)
        );
        if($attributes==DelegatingMethodSecurityMetadataSource::NULL_MARK)
            return null;
        return $attributes;
    }

    protected function logDebug($message, array $context = array())
    {
        if($this->logger==null || !$this->debug)
            return;
        $this->logger->debug($message,$context);
    }
}