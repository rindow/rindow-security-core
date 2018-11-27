<?php
namespace Rindow\Security\Core\Authentication\Provider;

use Interop\Lenient\Security\Authentication\Authentication;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;
use Rindow\Security\Core\Authentication\UserDetails\Provider\AbstractUserDetailsAuthenticationProvider;
use Rindow\Security\Core\Authentication\Exception;
use Rindow\Security\Core\Crypto\PasswordEncoder\LegacyPasswordEncoder;

class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
{
    const TOKEN_CLASS = 'Rindow\\Security\\Core\\Authentication\\Token\\UsernamePasswordAuthenticationToken';

    protected $passwordEncoder;    /*PasswordEncoder*/

    public function __construct($userDetailsService,$passwordEncoder=null,
        $preAuthenticationChecks=null,$postAuthenticationChecks=null)
    {
        parent::__construct($userDetailsService,$preAuthenticationChecks,$postAuthenticationChecks);
        if($passwordEncoder)
            $this->setPasswordEncoder($passwordEncoder);
        else
            $this->setPasswordEncoder(new LegacyPasswordEncoder());
    }

    public function setPasswordEncoder(/*PasswordEncoder*/ $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    public function getPasswordEncoder()
    {
        return $this->passwordEncoder;
    }

    protected function assertAuthenticationTokenType(Authentication $authentication)
    {
        if(!($authentication instanceof UsernamePasswordAuthenticationToken))
            throw new Exception\InvalidArgumentException('Only UsernamePasswordAuthenticationToken is supported.');
    }

    protected function retrieveUser(
        $username, Authentication $authentication)
    {
        $loadedUser = null;
        try {
            $loadedUser = $this->getUserDetailsService()->loadUserByUsername($username);
        } catch(Exception\UsernameNotFoundException $e) {
            throw $e;
        }
        catch (\Exception $e) {
            throw new Exception\InternalAuthenticationServiceException(
                    $e->getMessage(), $e->getCode(), $e);
        }

        if ($loadedUser == null) {
            throw new Exception\InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }
        return $loadedUser;
    }

    protected function authenticationChecks(
        UserDetails $userDetails,
        Authentication $authentication)
    {
        if($authentication->isAuthenticated())
            return;

        if($authentication->getCredentials() == null) {
            throw new Exception\BadCredentialsException("Bad credentials");
        }

        $presentedPassword = strval($authentication->getCredentials());

        if (!$this->passwordEncoder->isPasswordValid(
            $userDetails->getPassword(),
            $presentedPassword)) {
            throw new Exception\BadCredentialsException("Bad credentials");
        }
    }

    protected function createSuccessAuthentication(
            $principal,
            Authentication $authentication,
            UserDetails $user)
    {
        $result = new UsernamePasswordAuthenticationToken(
                $principal,
                null,//$authentication->getCredentials(),
                $user->getAuthorities());
        $result->setDetails($authentication->getDetails());

        return $result;
    }

    public function supports($token)
    {
        if(is_string($token)) {
            return ($token==self::TOKEN_CLASS) || is_subclass_of($token,self::TOKEN_CLASS);
        } else {
            if($token instanceof UsernamePasswordAuthenticationToken)
                return true;
            else
                return false;
        }
    }

    public function createToken($principal,$credentials)
    {
        return new UsernamePasswordAuthenticationToken($principal,$credentials);
    }
}
