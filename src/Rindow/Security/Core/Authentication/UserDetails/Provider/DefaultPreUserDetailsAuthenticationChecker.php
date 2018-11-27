<?php
namespace Rindow\Security\Core\Authentication\UserDetails\Provider;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsChecker;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Rindow\Security\Core\Authentication\Exception;

class DefaultPreUserDetailsAuthenticationChecker implements UserDetailsChecker
{
    public function check(/*UserDetails*/ $user)
    {
        if(!$user->isAccountNonLocked()) {
            throw new Exception\LockedException("User account is locked");
        }
        if(!$user->isEnabled()) {
            throw new Exception\DisabledException("User is disabled");
        }
        if(!$user->isAccountNonExpired()) {
            throw new Exception\AccountExpiredException("User account has expired");
        }
    }
}