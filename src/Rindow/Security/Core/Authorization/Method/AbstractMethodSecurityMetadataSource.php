<?php
namespace Rindow\Security\Core\Authorization\Method;

use Interop\Lenient\Security\Authorization\SecurityMetadataSource;
//use Rindow\Aop\ProceedingJoinPointInterface;
use Rindow\Aop\JoinPointInterface;

abstract class AbstractMethodSecurityMetadataSource implements SecurityMetadataSource
{
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
}