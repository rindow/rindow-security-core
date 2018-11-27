<?php
namespace Rindow\Security\Core\Authorization\Method;

use Rindow\Security\Core\Authorization\Support\AbstractAccessRightsBoundary;
//use Rindow\Aop\ProceedingJoinPointInterface;
use Rindow\Aop\JoinPointInterface;


class MethodSecurityAdvisor extends AbstractAccessRightsBoundary
{
    protected function proceed($invocation)
    {
        return $invocation->proceed();
    }

    public function supports($invocation)
    {
        if(!is_object($invocation))
            return false;
        //if($invocation instanceof ProceedingJoinPointInterface)
        if($invocation instanceof JoinPointInterface)
            return true;
        else
            return false;
    }

    protected function onPublicAccess($object)
    {
    }

    protected function onAuthorized($object)
    {
    }

    protected function onAuthorizationFailure($object, $attributes, $authenticated,$accessDeniedException)
    {
    }

    protected function buildRunAs($authenticated, $object, $attributes)
    {
    }
}
