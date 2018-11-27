<?php
namespace Rindow\Security\Core\Authorization\Method;

use Rindow\Stdlib\Cache\CacheHandlerTemplate;

class DelegatingMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource
{
    const NULL_MARK = '$$$$NULL$$$$';
    protected $methodSecurityMetadataSources = array();
    protected $cache;
    protected $debug;
    protected $logger;

    static public function factory($serviceLocator,$componentName,$args)
    {
        $methodSecurityMetadataSources = array();
        if(isset($args['sources'])) {
            foreach($args['sources'] as $name) {
                $methodSecurityMetadataSources[] = $serviceLocator->get($name);
            }
        }
        $instance = new self($methodSecurityMetadataSources);
        if(isset($args['debug'])) {
            $instance->setDebug($args['debug']);
        }
        if(isset($args['logger'])) {
            $logger = $serviceLocator->get($args['logger']);
            $instance->setLogger($logger);
        }
        return $instance;
    }

    public function __construct(array $methodSecurityMetadataSources = null)
    {
        if($methodSecurityMetadataSources)
            $this->setMethodSecurityMetadataSources($methodSecurityMetadataSources);
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

    protected function getCache()
    {
        if($this->cache)
            return $this->cache;
        $handler = new CacheHandlerTemplate(__CLASS__);
        $this->cache = $handler->getCache('attr');
        return $this->cache;
    }

    public function getAttributes($invocation)
    {
        $signatureString = $invocation->getSignatureString();
        $this->logDebug('Get attributes at :'.$signatureString);
        $cache = $this->getCache();
        $methodSecurityMetadataSources = $this->methodSecurityMetadataSources;
        $attributes = $cache->get($signatureString,null,
            function ($cache,$path,&$value) use ($invocation,$methodSecurityMetadataSources) {
                foreach($methodSecurityMetadataSources as $methodSecurityMetadataSource) {
                    $attributes = $methodSecurityMetadataSource->getAttributes($invocation);
                    if($attributes===null)
                        continue;
                    $value = $attributes;
                    return true;
                }
                $value = DelegatingMethodSecurityMetadataSource::NULL_MARK;
                return true;
            }
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