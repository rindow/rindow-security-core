<?php
namespace Rindow\Security\Core\Authentication\Provider;

use Interop\Lenient\Security\Authentication\AuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Exception;

class AnonymousAuthenticationProvider implements AuthenticationProvider
{
    const TOKEN_CLASS = 'Rindow\\Security\\Core\\Authentication\\Token\\AnonymousAuthenticationToken';
    protected $keyHash;
    protected $defaultPrincipal;
    protected $defaultAuthorities;

    public function __construct($key,$defaultPrincipal=null,$defaultAuthorities=null)
    {
        if(empty($key))
            throw new Exception\InvalidArgumentException('the secret key is required');
        $this->setKey($key);
        if($defaultPrincipal)
            $this->setDefaultPrincipal($defaultPrincipal);
        if($defaultAuthorities)
            $this->setDefaultAuthorities($defaultAuthorities);
    }

    protected function setKey($key)
    {
        $this->keyHash = sha1($key);
    }

    protected function setDefaultPrincipal($defaultPrincipal)
    {
        $this->defaultPrincipal = $defaultPrincipal;
    }

    protected function setDefaultAuthorities($defaultAuthorities)
    {
        $authorities = array();
        foreach ($defaultAuthorities as $key => $switch) {
            if(!$switch)
                continue;
            $authorities[] = $key;
        }
        $this->defaultAuthorities = $authorities;
    }

    public function authenticate(/*Authentication*/ $authentication)
    {
        if(!($authentication instanceof AnonymousAuthenticationToken)) {
            throw new Exception\InvalidArgumentException('Only AnonymousAuthenticationToken is supported.');
        }

        if($this->getKeyHash() !== $authentication->getKeyHash()) {
            throw new Exception\BadCredentialsException(
                'The presented AnonymousAuthenticationToken does not contain the expected key');
        }
        return $authentication;
    }

    public function getKeyHash()
    {
        if(empty($this->keyHash))
            throw new Exception\InvalidArgumentException('A Sercret key is required');
        return $this->keyHash;
    }

    public function supports($authentication)
    {
        if(is_string($authentication)) {
            return ($authentication==self::TOKEN_CLASS) || is_subclass_of($authentication,self::TOKEN_CLASS);
        } else {
            if($authentication instanceof AnonymousAuthenticationToken)
                return true;
            else
                return false;
        }
    }

    public function createToken($principal=null,array $authorities=null)
    {
        if($principal==null)
            $principal = $this->defaultPrincipal;
        if($authorities==null)
            $authorities = $this->defaultAuthorities;
        return new AnonymousAuthenticationToken($this->getKeyHash(), $principal, $authorities);
    }
}
