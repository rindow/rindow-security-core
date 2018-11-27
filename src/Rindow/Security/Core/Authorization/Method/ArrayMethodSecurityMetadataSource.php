<?php
namespace Rindow\Security\Core\Authorization\Method;

class ArrayMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource
{
    protected $config;

    public function setConfig($config)
    {
        $this->config = $config;
    }

    public function getAttributes($invocation)
    {
        if(!$this->supports($invocation))
            return null;

        $signatureString = $invocation->getSignatureString();
        if(!isset($this->config[$signatureString]))
            return null;

        return $this->config[$signatureString];
    }
}