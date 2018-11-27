<?php
namespace Rindow\Security\Core\Authentication\UserDetails\Provider;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsChecker;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Rindow\Security\Core\Authentication\Exception;

class DefaultPostUserDetailsAuthenticationChecker implements UserDetailsChecker
{
    public function check(/*UserDetails*/ $user)
    {
        if (!$user->isCredentialsNonExpired()) {
            throw new Exception\CredentialsExpiredException("User credentials have expired");
        }
    }
}