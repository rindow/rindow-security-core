<?php
namespace Rindow\Security\Core\Authorization\Support;

use Interop\Lenient\Security\Authentication\SecurityContext;
use Interop\Lenient\Security\Authentication\AuthenticationTrustResolver;
use Interop\Lenient\Security\Authorization\AccessDecisionManager;
use Interop\Lenient\Security\Authorization\AfterInvocationManager;
use Interop\Lenient\Security\Authorization\SecurityMetadataSource;

use Rindow\Security\Core\Authentication\Exception\AuthenticationCredentialsNotFoundException;
use Rindow\Security\Core\Authorization\Exception;
use Rindow\Security\Core\Authorization\Exception\AccessDeniedException;
use Rindow\Security\Core\Authorization\Exception\AuthenticationRequiredException;
use Rindow\Security\Core\Authorization\Exception\FullAuthenticationRequiredException;
use Rindow\Security\Core\Authorization\Vote\AuthenticatedVoter;

abstract class AbstractAccessRightsBoundary
{
    protected $authenticationManager;
    protected $securityMetadataSource;
    protected $securityContext;
    protected $accessDecisionManager;
    protected $afterInvocationManager;
    protected $alwaysReauthenticate = false;
    protected $rejectPublicInvocations = false;
    protected $authenticationTrustResolver;
    protected $throwAuthenticationRequiredException = true;

    abstract public function supports($object);
    abstract protected function proceed(/*Object*/ $object);
    abstract protected function onPublicAccess($object);
    abstract protected function onAuthorized($object);
    abstract protected function onAuthorizationFailure($object, $attributes, $authenticated,$accessDeniedException);
    abstract protected function buildRunAs($authenticated, $object, $attributes);

    public function setAccessDecisionManager(AccessDecisionManager $accessDecisionManager)
    {
        $this->accessDecisionManager = $accessDecisionManager;
    }

    public function getAccessDecisionManager()
    {
        return $this->accessDecisionManager;
    }

    public function setSecurityContext(SecurityContext $securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function getSecurityContext()
    {
        return $this->securityContext;
    }

    public function setAfterInvocationManager(AfterInvocationManager $afterInvocationManager)
    {
        $this->afterInvocationManager = $afterInvocationManager;
    }

    public function getAfterInvocationManager()
    {
        return $this->afterInvocationManager;
    }

    public function setAuthenticationManager($authenticationManager)
    {
        $this->authenticationManager = $authenticationManager;
    }

    public function getAuthenticationManager()
    {
        return $this->authenticationManager;
    }

    public function setSecurityMetadataSource(SecurityMetadataSource $securityMetadataSource)
    {
        $this->securityMetadataSource = $securityMetadataSource;
    }

    public function getSecurityMetadataSource()
    {
        return $this->securityMetadataSource;
    }

    public function setAuthenticationTrustResolver(AuthenticationTrustResolver $authenticationTrustResolver)
    {
        $this->authenticationTrustResolver = $authenticationTrustResolver;
    }

    public function setThrowAuthenticationRequiredException($throwAuthenticationRequiredException)
    {
        $this->throwAuthenticationRequiredException = $throwAuthenticationRequiredException;
    }

    public function isThrowAuthenticationRequiredException()
    {
        return $this->throwAuthenticationRequiredException;
    }

    public function getAuthenticationTrustResolver()
    {
        return $this->authenticationTrustResolver;
    }

    public function setAlwaysReauthenticate($alwaysReauthenticate)
    {
        $this->alwaysReauthenticate = $alwaysReauthenticate;
    }

    public function isAlwaysReauthenticate()
    {
        return $this->alwaysReauthenticate;
    }

    public function setRejectPublicInvocations($rejectPublicInvocations)
    {
        $this->rejectPublicInvocations = $rejectPublicInvocations;
    }

    public function isRejectPublicInvocations()
    {
        return $this->rejectPublicInvocations;
    }

    public function beforeAccess(/*Object*/ $object)
    {
        $this->beforeInvocation($object);
    }

    public function access(/*Object*/ $object)
    {
        $status = $this->beforeInvocation($object);

        $result = null;
        try {
            $result = $this->proceed($object);
            $this->finallyInvocation($status);
        } catch(\Exception $e) {
            $this->finallyInvocation($status);
            throw $e;
        }
        return $this->afterInvocation($status, $result);
    }

    /**
     * @return InterceptorStatus $status
     */
    protected function beforeInvocation(/*Object*/ $object)
    {
        $objectType = is_object($object) ? get_class($object) : gettype($object);

        if(!$this->supports($object)) {
            throw new Exception\InvalidArgumentException(
                'Security invocation attempted for object "'.$objectType.'" is not supported.');
        }

        $attributes = $this->securityMetadataSource->getAttributes($object);

        if (empty($attributes)) {
            if ($this->rejectPublicInvocations) {
                throw new Exception\InvalidArgumentException(
                        "Secure object invocation "
                                . $objectType
                                . " was denied as public invocations are not allowed via this interceptor. "
                                . "This indicates a configuration error because the "
                                . "rejectPublicInvocations property is set to 'true'");
            }

            $this->onPublicAccess($object);

            return null; // no further work post-invocation
        }

        if ($this->securityContext->getAuthentication() == null) {
            throw new AuthenticationCredentialsNotFoundException(
                    'An Authentication object was not found in the SecurityContext');
        }

        $authenticated = $this->authenticateIfRequired();

        try {
            $this->accessDecisionManager->decide($authenticated, $object, $attributes);
        }
        catch (AccessDeniedException $accessDeniedException) {
            $accessDeniedException = $this->translateToAuthenticateRequiredException(
                $accessDeniedException, $authenticated, $object, $attributes);
            $this->onAuthorizationFailure(
                $object, $attributes, $authenticated, $accessDeniedException);
            throw $accessDeniedException;
        }

        $this->onAuthorized($object, $attributes, $authenticated);

        $runAs = $this->buildRunAs($authenticated, $object, $attributes);

        if ($runAs == null) {
            return new SecurityAdvisorStatus($this->securityContext, false,
                    $attributes, $object);
        }
        else {
            $origAuth = $this->securityContext->getAuthentication();
            $this->securityContext->setAuthentication($runAs);

            return new SecurityAdvisorStatus($origAuth, true, $attributes, $object);
        }
    }

    protected function translateToAuthenticateRequiredException(
        $accessDeniedException, $authenticated, $object, $attributes)
    {
        if(!$this->throwAuthenticationRequiredException)
            return $accessDeniedException;
        if(in_array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY, $attributes) &&
            ($this->authenticationTrustResolver->isAnonymous($authenticated)||
             $this->authenticationTrustResolver->isRememberMe($authenticated))) {
            return new FullAuthenticationRequiredException('Full authentication required.',0,$accessDeniedException);
        }
        if(in_array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED, $attributes) &&
            $this->authenticationTrustResolver->isAnonymous($authenticated)) {
            return new AuthenticationRequiredException('Authentication required.',0,$accessDeniedException);
        }
        return $accessDeniedException;
    }

    protected function finallyInvocation(SecurityAdvisorStatus $status=null)
    {
        if ($status != null && $status->isContextHolderRefreshRequired()) {
            $this->securityContext->setAuthentication($status->getAuthentication());
        }
    }

    /**
     * @return Object　$returnedObject
     */
    protected function afterInvocation(SecurityAdvisorStatus $status=null, $returnedObject=null)
    {
        if ($status == null) {
            // public object
            return $returnedObject;
        }

        $this->finallyInvocation($status); // continue to clean in this method for passivity

        if ($this->afterInvocationManager != null) {
            // Attempt after invocation handling
            try {
                $returnedObject = $this->afterInvocationManager->decide(
                    $status->getAuthentication(),
                    $status->getSecureObject(),
                    $status->getAttributes(),
                    $returnedObject);
            } catch (AccessDeniedException $accessDeniedException) {
                $accessDeniedException = $this->translateToAuthenticateRequiredException(
                    $accessDeniedException, $authenticated, $object, $attributes);
                $this->onAuthorizationFailure(
                        $status->getSecureObject(),
                        $status->getAttributes(),
                        $status->getAuthentication(),
                        $accessDeniedException);

                throw $accessDeniedException;
            }
        }

        return $returnedObject;
    }

    private function authenticateIfRequired()
    {
        $authentication = $this->securityContext->getAuthentication();

        if($authentication->isAuthenticated() && !$this->alwaysReauthenticate) {
            return $authentication;
        }

        $authentication = $this->authenticationManager->authenticate($authentication);

        $this->securityContext->setAuthentication($authentication);

        return $authentication;
    }
}
