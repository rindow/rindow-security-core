<?php
namespace Rindow\Security\Core\Authentication\Support;

use Interop\Lenient\Security\Authentication\SecurityContext as SecurityContextInterface;

class SecurityContext implements SecurityContextInterface
{
    protected $strage;
    protected $key;
    protected $defaultAuthentication;
    protected $lifeTime;

    public function __construct($strage=null,$key=null)
    {
        $this->setStrage($strage);
        $this->setKey($key);
    }

    public function setKey($key)
    {
        $this->key = $key;
    }

    public function setStrage($strage)
    {
        $this->strage = $strage;
    }

    public function getStrage()
    {
        return $this->strage;
    }

    public function setLifeTime($lifeTime)
    {
        $this->lifeTime = $lifeTime;
    }

    public function getAuthentication()
    {
        $authentication = $this->strage->get($this->key.'.Authentication');
        if(!$authentication)
            return $this->defaultAuthentication;
        if($this->lifeTime) {
            $lastUpdate = $this->strage->get($this->key.'.LastUpdate');
            if($this->lifeTime <= time()-$lastUpdate) {
                $this->strage->set($this->key.'.LastUpdate',0);
                $this->strage->set($this->key.'.Authentication',null);
                return $this->defaultAuthentication;
            }
        }
        return $authentication;
    }

    public function setAuthentication(/*Authentication*/$authentication)
    {
        $this->strage->set($this->key.'.LastUpdate',time());
        $this->strage->set($this->key.'.Authentication',$authentication);
    }

    public function setDefaultAuthentication(/*Authentication*/$defaultAuthentication)
    {
        $this->defaultAuthentication = $defaultAuthentication;
    }
}