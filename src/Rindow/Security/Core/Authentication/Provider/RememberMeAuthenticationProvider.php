<?php
namespace Rindow\Security\Core\Authentication\Provider;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Interop\Lenient\Security\Authentication\AuthenticationProvider;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Exception;

class RememberMeAuthenticationProvider implements AuthenticationProvider
{
    const TOKEN_CLASS = 'Rindow\\Security\\Core\\Authentication\\Token\\RememberMeAuthenticationToken';
    protected $keyHash;

    public function __construct($key)
    {
        if(empty($key))
            throw new Exception\InvalidArgumentException('the secret key is required');
        $this->setKey($key);
    }

    protected function setKey($key)
    {
        $this->keyHash = sha1($key);
    }

    public function authenticate(/*Authentication*/ $authentication)
    {
        if(!($authentication instanceof RememberMeAuthenticationToken)) {
            throw new Exception\InvalidArgumentException('Only RememberMeAuthenticationToken is supported.');
        }

        $user = $authentication->getPrincipal();
        if($this->getKeyHash() !== $authentication->getKeyHash()) {
            throw new Exception\BadCredentialsException(
                'The presented RememberMeAuthenticationToken does not contain the expected key');
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
            if($authentication instanceof RememberMeAuthenticationToken)
                return true;
            else
                return false;
        }
    }

    public function createToken($principal,array $authorities=null)
    {
        return new RememberMeAuthenticationToken($this->getKeyHash(), $principal, $authorities);
    }
}
