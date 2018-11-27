<?php
namespace Rindow\Security\Core\Authentication\Support;

use Interop\Lenient\Security\Authentication\AuthenticationTrustResolver as AuthenticationTrustResolverInterface;

class AuthenticationTrustResolver implements AuthenticationTrustResolverInterface
{
    protected $anonymousClass  = 'Rindow\\Security\\Core\\Authentication\\Token\\AnonymousAuthenticationToken';
    protected $rememberMeClass = 'Rindow\\Security\\Core\\Authentication\\Token\\RememberMeAuthenticationToken';
    
    public function setAnonymousClass($anonymousClass)
    {
        $this->anonymousClass = $anonymousClass;
    }

    public function getAnonymousClass()
    {
        return $this->anonymousClass;
    }
    
    public function setRememberMeClass($rememberMeClass)
    {
        $this->rememberMeClass = $rememberMeClass;
    }
    public function getRememberMeClass()
    {
        return $this->rememberMeClass;
    }

    public function isAnonymous(/*Authentication*/ $authentication)
    {
        if (($this->anonymousClass == null) || ($authentication == null)) {
            return false;
        }

        return is_a($authentication, $this->anonymousClass);
    }

    public function isRememberMe(/*Authentication*/ $authentication)
    {
        if (($this->rememberMeClass == null) || ($authentication == null)) {
            return false;
        }

        return is_a($authentication, $this->rememberMeClass);
    }
}