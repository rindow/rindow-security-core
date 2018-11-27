<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;

abstract class AbstractAclVoter implements AccessDecisionVoter
{
    public function getDomainObjectInstance(/*MethodInvocation*/ invocation) 
    {
        # code...
    }
    public function getProcessDomainObjectClass()
    {
        # code...
    }
    public function setProcessDomainObjectClass(/*Class<?>*/ $processDomainObjectClass) 
    {
        # code...
    }
    public function supports(/*ConfigAttribute*/ $attribute)
    {}
}