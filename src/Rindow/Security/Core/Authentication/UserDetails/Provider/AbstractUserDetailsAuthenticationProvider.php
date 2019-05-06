<?php
namespace Rindow\Security\Core\Authentication\UserDetails\Provider;

use Interop\Lenient\Security\Authentication\Authentication;
use Interop\Lenient\Security\Authentication\AuthenticationProvider;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsService;
use Rindow\Security\Core\Authentication\Exception;
use Rindow\Security\Core\Authentication\Exception\ContainsRejectedAuthentication;

abstract class AbstractUserDetailsAuthenticationProvider implements AuthenticationProvider
{
    protected $hideUserNotFoundExceptions = true;
    protected $forcePrincipalAsString = false;
    protected $forceRetrieveUserDetails = false;
    protected $userDetailsService; /*UserDetailsService */
    protected $preAuthenticationChecks;
    protected $postAuthenticationChecks;

    /**
     * @param Authentication $authentication
     * @return void
     */
    abstract protected function assertAuthenticationTokenType(Authentication $authentication);

    /**
     * @param String $username
     * @param Authentication $authentication
     * @return UserDetails
     */
    abstract protected function retrieveUser(
        $username,
        Authentication $authentication);

    /**
     * @param UserDetails $userDetails
     * @param Authentication $authentication
     * @return void
     */
    abstract protected function authenticationChecks(
        UserDetails $userDetails,
        Authentication $authentication);

    public function __construct($userDetailsService=null,$preAuthenticationChecks=null,$postAuthenticationChecks=null)
    {
        if($userDetailsService)
            $this->setUserDetailsService($userDetailsService);
        if($preAuthenticationChecks)
            $this->preAuthenticationChecks = $preAuthenticationChecks;
        else
            $this->preAuthenticationChecks = new DefaultPreUserDetailsAuthenticationChecker();
        if($postAuthenticationChecks)
            $this->postAuthenticationChecks = $postAuthenticationChecks;
        else
            $this->postAuthenticationChecks = new DefaultPostUserDetailsAuthenticationChecker();
    }

    public function setUserDetailsService(UserDetailsService $userDetailsService)
    {
        $this->userDetailsService = $userDetailsService;
    }

    protected function getUserDetailsService()
    {
        return $this->userDetailsService;
    }

    public function setHideUserNotFoundExceptions($hideUserNotFoundExceptions)
    {
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    public function setForcePrincipalAsString($forcePrincipalAsString)
    {
        $this->forcePrincipalAsString = $forcePrincipalAsString;
    }

    public function setForceRetrieveUserDetails($forceRetrieveUserDetails)
    {
        $this->forceRetrieveUserDetails = $forceRetrieveUserDetails;
    }

    public function setPreAuthenticationChecks($preAuthenticationChecks)
    {
        $this->preAuthenticationChecks = $preAuthenticationChecks;
    }

    public function setPostAuthenticationChecks($postAuthenticationChecks)
    {
        $this->postAuthenticationChecks = $postAuthenticationChecks;
    }

    public function authenticate(/*Authentication*/ $authentication)
    {
        $this->assertAuthenticationTokenType($authentication);

        $username = $authentication->getName();
        if($username==null)
            $username = 'NONE_PROVIDED';

        try {
            $user = null;
            if(!$this->forceRetrieveUserDetails)
                $user = $authentication->getPrincipal();
            if(!($user instanceof UserDetails))
                $user = $this->retrieveUser($username,$authentication);
        } catch(Exception\UsernameNotFoundException $e) {
            if($this->hideUserNotFoundExceptions)
                throw new Exception\BadCredentialsException('Bad credentials',0,$e);
            throw $e;
        }
        if($user==null)
            throw new Exception\DomainException('retrieveUser returned null - a violation of the interface contract.');

        $this->preAuthenticationChecks->check($user);
        $this->authenticationChecks($user,$authentication);
        try {
            $this->postAuthenticationChecks->check($user);
        } catch(Exception\AuthenticationException $e) {
            $principalToReturn = $user;
            if($this->forcePrincipalAsString) {
                $principalToReturn = $user->getUsername();
            }
            $rejectedAuthentication = $this->createSuccessAuthentication($principalToReturn, $authentication, $user);
            if($e instanceof ContainsRejectedAuthentication) {
                $e->setAuthentication($rejectedAuthentication);
            }
            throw $e;
        }

        $principalToReturn = $user;
        if($this->forcePrincipalAsString) {
            $principalToReturn = $user->getUsername();
        }
        return $this->createSuccessAuthentication($principalToReturn, $authentication, $user);
    }
}