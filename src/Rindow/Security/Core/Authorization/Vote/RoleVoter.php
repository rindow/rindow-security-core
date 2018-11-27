<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;

class RoleVoter implements AccessDecisionVoter
{
    protected $rolePrefix = 'ROLE_';

    public function getRolePrefix()
    {
        return $this->rolePrefix;
    }

    public function setRolePrefix(/*String*/ $rolePrefix)
    {
        $this->rolePrefix = $rolePrefix;
    }

    public function supports(/*ConfigAttribute*/ $attribute)
    {
        if(is_string($attribute) && strpos($attribute, $this->rolePrefix)===0)
            return true;
        return false;
    }

    public function vote(/*Authentication*/ $authentication, $object, array $attributes)
    {
        if($authentication==null)
            return AccessDecisionVoter::ACCESS_DENIED;
        $result = AccessDecisionVoter::ACCESS_ABSTAIN;
        $authorities = $this->extractAuthorities($authentication);
        foreach ($attributes as $attribute) {
            if(!$this->supports($attribute))
                continue;
            $result = AccessDecisionVoter::ACCESS_DENIED;
            foreach ($authorities as $authority) {
                if($attribute==$authority)
                    return AccessDecisionVoter::ACCESS_GRANTED;
            }
        }
        return $result;
    }

    protected function extractAuthorities($authentication)
    {
        return $authentication->getAuthorities();
    }
}