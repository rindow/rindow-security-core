<?php
namespace Rindow\Security\Core\Authentication\Token;

use Rindow\Security\Core\Authentication\Exception;

class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken
{
    public function __construct($principal,$credentials,array $authorities=null)
    {
        parent::__construct($authorities);

        $this->setPrincipal($principal);
        $this->setCredentials($credentials);
        if($authorities!==null)
            parent::setAuthenticated(true);
    }

    public function setAuthenticated($authenticated)
    {
        if($authenticated)
            throw new Exception\InvalidArgumentException(
                "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        parent::setAuthenticated($authenticated);
    }
}