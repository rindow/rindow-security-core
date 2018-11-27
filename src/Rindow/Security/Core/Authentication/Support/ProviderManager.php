<?php
namespace Rindow\Security\Core\Authentication\Support;

use Rindow\Security\Core\Authentication\Exception;
use Interop\Lenient\Security\Authentication\AuthenticationManager;
//use Rindow\Security\Core\Authentication\AuthenticationToken;

class ProviderManager implements AuthenticationManager
{
    protected $providers = array();
    protected $parent;

    public function __construct(array $providers,/*AuthenticationManager*/$parent=null)
    {
        $this->providers = $providers;
        if(!$this->providers)
            throw new Exception\DomainException('providers are not specifed.');
        if($parent)
            $this->setParent($parent);
    }

    public function addProvier($provider)
    {
        $this->providers[] = $provider;
    }

    public function getProviders()
    {
        return $this->providers;
    }

    public function setParent(/*AuthenticationManager*/$parent)
    {
        $this->parent = $parent;
    }

    public function authenticate(/*AuthenticationToken*/$token)
    {
        $authenticatedToken = null;
        $exception = null;
        foreach ($this->providers as $provider) {
            if(!$provider->supports($token))
                continue;
            try {
                $authenticatedToken = $provider->authenticate($token);
                if($authenticatedToken)
                    break;
            } catch(Exception\AuthenticationException $e) {
                $exception = $e;
            }
        }

        if(!$authenticatedToken && $this->parent) {
            try {
                $authenticatedToken = $this->parent->authenticate($token);
            } catch(Exception\ProviderNotFoundException $e) {
                ;
            } catch(Exception\AuthenticationException $e) {
                if($exception==null)
                    $exception = $e;
            }
        }

        if($authenticatedToken)
            return $authenticatedToken;

        if($exception==null)
            throw new Exception\ProviderNotFoundException('Supported authentication provider is not found.');
        throw new Exception\BadCredentialsException($exception->getMessage(),$exception->getCode(),$exception);
    }
}
