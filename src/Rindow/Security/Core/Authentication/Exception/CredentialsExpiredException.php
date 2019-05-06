<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\CredentialsExpiredException as CredentialsExpiredExceptionInterface;

class CredentialsExpiredException
extends AuthenticationException
implements CredentialsExpiredExceptionInterface,ContainsRejectedAuthentication
{
    protected $authentication;
    public function setAuthentication($authentication)
    {
        $this->authentication = $authentication;
    }

    public function getAuthentication()
    {
        return $this->authentication;
    }
}
