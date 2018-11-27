<?php
namespace Rindow\Security\Core\Authorization\Support;

class SecurityAdvisorStatus
{
    private $authentication;
    private $attributes = array();
    private $secureObject;
    private $contextHolderRefreshRequired = false;

    // ~ Constructors
    // ===================================================================================================

    public function __construct(
        /*SecurityContext*/ $authentication,
        $contextHolderRefreshRequired,
        array $attributes,
        $secureObject)
    {
        $this->authentication = $authentication;
        $this->contextHolderRefreshRequired = $contextHolderRefreshRequired;
        $this->attributes = $attributes;
        $this->secureObject = $secureObject;
    }

    // ~ Methods
    // ========================================================================================================

    public function getAttributes()
    {
        return $this->attributes;
    }

    public function getAuthentication()
    {
        return $this->authentication;
    }

    public function getSecureObject()
    {
        return $this->secureObject;
    }

    public function isContextHolderRefreshRequired()
    {
        return $this->contextHolderRefreshRequired;
    }
}
