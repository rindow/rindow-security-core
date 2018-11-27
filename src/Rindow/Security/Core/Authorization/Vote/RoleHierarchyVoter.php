<?php
namespace Rindow\Security\Core\Authorization\Vote;

class RoleHierarchyVoter extends RoleVoter
{
    protected $roleHierarchy;

    public function __construct($roleHierarchy = null)
    {
        if($roleHierarchy)
            $this->setRoleHierarchy($roleHierarchy);
    }

    public function setRoleHierarchy($roleHierarchy)
    {
        $this->roleHierarchy = $roleHierarchy;
    }

    protected function extractAuthorities($authentication)
    {
        return $this->roleHierarchy->getReachableGrantedAuthorities(
            $authentication->getAuthorities());
    }
}
