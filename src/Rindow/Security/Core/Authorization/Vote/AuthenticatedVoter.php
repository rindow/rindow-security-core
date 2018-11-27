<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;

class AuthenticatedVoter implements AccessDecisionVoter
{
    const IS_AUTHENTICATED_ANONYMOUSLY = 'IS_AUTHENTICATED_ANONYMOUSLY';
    const IS_AUTHENTICATED_FULLY       = 'IS_AUTHENTICATED_FULLY';
    const IS_AUTHENTICATED_REMEMBERED  = 'IS_AUTHENTICATED_REMEMBERED';

    protected $authenticationTrustResolver;

    public function __construct($authenticationTrustResolver = null)
    {
        if($authenticationTrustResolver)
            $this->setAuthenticationTrustResolver($authenticationTrustResolver);
    }

    public function setAuthenticationTrustResolver(/*AuthenticationTrustResolver*/ $authenticationTrustResolver)
    {
        $this->authenticationTrustResolver = $authenticationTrustResolver;
    }

    public function supports(/*ConfigAttribute*/ $attribute)
    {
        if(is_string($attribute) &&
            ( self::IS_AUTHENTICATED_FULLY == $attribute ||
                self::IS_AUTHENTICATED_REMEMBERED == $attribute ||
                self::IS_AUTHENTICATED_ANONYMOUSLY == $attribute)) {
            return true;
        }
        else {
            return false;
        }
    }

    protected function isFullyAuthenticated(/*Authentication*/ $authentication)
    {
        return (!$this->authenticationTrustResolver->isAnonymous($authentication) &&
                !$this->authenticationTrustResolver->isRememberMe($authentication));
    }

    public function vote(/*Authentication*/ $authentication, $object, array $attributes)
    {
        $result = AccessDecisionVoter::ACCESS_ABSTAIN;
        foreach ($attributes as $attribute) {
            if(!$this->supports($attribute))
                continue;
            $result = AccessDecisionVoter::ACCESS_DENIED;
            switch ($attribute) {
                case self::IS_AUTHENTICATED_FULLY:
                    if ($this->isFullyAuthenticated($authentication)) {
                        return AccessDecisionVoter::ACCESS_GRANTED;
                    }
                    break;
                case self::IS_AUTHENTICATED_REMEMBERED:
                    if ($this->authenticationTrustResolver->isRememberMe($authentication) ||
                        $this->isFullyAuthenticated($authentication)) {
                        return AccessDecisionVoter::ACCESS_GRANTED;
                    }
                    break;
                case self::IS_AUTHENTICATED_ANONYMOUSLY:
                    if ($this->authenticationTrustResolver->isAnonymous($authentication) ||
                        $this->authenticationTrustResolver->isRememberMe($authentication) ||
                        $this->isFullyAuthenticated($authentication)) {
                        return AccessDecisionVoter::ACCESS_GRANTED;
                    }
                    break;
            }
        }
        return $result;
    }
}