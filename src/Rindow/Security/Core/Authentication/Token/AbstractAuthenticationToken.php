<?php
namespace Rindow\Security\Core\Authentication\Token;

use Interop\Lenient\Security\Authentication\Authentication;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Interop\Lenient\Security\Authentication\UserDetails\CredentialsContainer;
use Serializable;

abstract class AbstractAuthenticationToken implements Authentication,Serializable
{
    protected $authenticated = false;
    protected $authorities = array();
    protected $principal;
    protected $credentials;
    protected $details;

    public function __construct(array $authorities=null)
    {
        if($authorities===null)
            return;
        $this->setAuthorities($authorities);
    }

    protected function setAuthorities(array $authorities)
    {
        foreach($authorities as $authority) {
            if ($authority == null) {
                throw new Exception\IllegalArgumentException(
                        "Authorities collection cannot contain any null elements");
            }
        }
        $this->authorities = $authorities;
    }

    public function getAuthorities()
    {
        return $this->authorities;
    }

    public function getName()
    {
        $principal = $this->getPrincipal();
        if($principal instanceof UserDetails)
            return $principal->getUsername();
        return strval($principal);
    }

    public function getPrincipal()
    {
        return $this->principal;
    }

    protected function setPrincipal($principal)
    {
        $this->principal = $principal;
    }

    public function getCredentials()
    {
        return $this->credentials;
    }

    protected function setCredentials($credentials)
    {
        $this->credentials = $credentials;
    }

    public function eraseCredentials()
    {
        if(is_string($this->getCredentials()))
            $this->setCredentials(null);
        $this->eraseSecret($this->getCredentials());
        $this->eraseSecret($this->getPrincipal());
        $this->eraseSecret($this->getDetails());
    }

    private function eraseSecret($secret)
    {
        if($secret instanceof CredentialsContainer)
            $secret->eraseCredentials();
    }

    public function setDetails($details)
    {
        $this->details = $details;
    }

    public function getDetails()
    {
        return $this->details;
    }

    public function isAuthenticated()
    {
        return $this->authenticated ;
    }

    public function setAuthenticated($authenticated)
    {
        $this->authenticated = $authenticated ? true : false;
    }

    public function serialize()
    {
        $principal = $this->getPrincipal();
        if(is_object($principal)) {
            $principal = clone $principal;
            $this->eraseSecret($principal);
        }
        $credentials = $this->getCredentials();
        if(is_object($credentials)) {
            $credentials = clone $credentials;
            $this->eraseSecret($credentials);
        } else {
            $credentials = null;
        }
        $details = $this->getDetails();
        if(is_object($details)) {
            $details = clone $details;
            $this->eraseSecret($details);
        }
        return serialize(array(
            $this->authenticated,
            $this->authorities,
            $principal,
            $credentials,
            $details,
        ));
    }

    public function unserialize($serialized)
    {
        list($this->authenticated,$this->authorities,$this->principal,$this->credentials,$this->details) = unserialize($serialized);
    }
}
