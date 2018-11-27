<?php
namespace Rindow\Security\Core\Authorization\Method;

use Rindow\Security\Core\Authorization\Annotation\PermitAll;
use Rindow\Security\Core\Authorization\Annotation\DenyAll;
use Rindow\Security\Core\Authorization\Annotation\RolesAllowed;
use Rindow\Security\Core\Authorization\Annotation\Authenticated;
use Rindow\Security\Core\Authorization\Annotation\FullyAuthenticated;
use Rindow\Security\Core\Authorization\Vote\AbsolutionVoter;
use Rindow\Security\Core\Authorization\Vote\AuthenticatedVoter;
use Rindow\Security\Core\Authorization\Exception;
use ReflectionClass;

class AnnotationMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource
{
    protected $annotationReader;
    protected $roleVoter;
    protected $rolePrefix;

    public function setAnnotationReader($annotationReader)
    {
        $this->annotationReader = $annotationReader;
    }

    public function setRolePrefix($rolePrefix)
    {
        $this->rolePrefix = $rolePrefix;
    }

    public function setRoleVoter($roleVoter)
    {
        $this->roleVoter = $roleVoter;
    }

    public function getAttributes($invocation)
    {
        if(!$this->supports($invocation))
            return null;

        if($this->rolePrefix===null)
            $this->rolePrefix = $this->roleVoter->getRolePrefix();

        $authorities = array();
        $classRef = new ReflectionClass($invocation->getSignature()->getClassName());
        $annotations = $this->annotationReader->getClassAnnotations($classRef);
        $classAuthorities = $this->translateAnnotations($annotations,$classRef);

        $methodRef = $classRef->getMethod($invocation->getSignature()->getMethod());
        $annotations = $this->annotationReader->getMethodAnnotations($methodRef);
        $methodAuthorities = $this->translateAnnotations($annotations,$methodRef);

        if(!empty($methodAuthorities)) {
            if($methodAuthorities[0]==AbsolutionVoter::PERMIT_ALL_ATTRIBUTE ||
                $methodAuthorities[0]==AbsolutionVoter::DENY_ALL_ATTRIBUTE) {
                return $this->uniqueAuthorities($methodAuthorities);
            }
        }

        if(!empty($methodAuthorities) && !empty($classAuthorities)) {
            if($classAuthorities[0]==AbsolutionVoter::PERMIT_ALL_ATTRIBUTE ||
                $classAuthorities[0]==AbsolutionVoter::DENY_ALL_ATTRIBUTE) {
                return $this->uniqueAuthorities($methodAuthorities);
            }
        }

        $authorities = array_merge($classAuthorities,$methodAuthorities);
        $authorities = $this->uniqueAuthorities($authorities);
        if(empty($authorities))
            return null;
        return $authorities;
    }

    protected function translateAnnotations($annotations,$ref)
    {
        $authorities = array();
        $hasAbsolution = false;
        $mutually = null;
        foreach ($annotations as $annotation) {
            if($hasAbsolution ||
                (count($authorities)>0 &&
                    (($annotation instanceof PermitAll) ||
                        ($annotation instanceof DenyAll)))) {
                $annotationName = substr(get_class($annotation), strrpos(get_class($annotation), '\\')+1);
                $location = $ref->getFileName().'('.$ref->getStartLine().')';
                throw new Exception\DomainException('@'.$annotationName.' is invalid. DenyAll and PermitAll annotations must be used exclusively with other annotations.:'.$location);
            }
            if($annotation instanceof PermitAll) {
                $hasAbsolution = true;
                array_unshift($authorities, AbsolutionVoter::PERMIT_ALL_ATTRIBUTE);
            } elseif($annotation instanceof DenyAll) {
                $hasAbsolution = true;
                array_unshift($authorities, AbsolutionVoter::DENY_ALL_ATTRIBUTE);
            } elseif($annotation instanceof RolesAllowed) {
                $roles = $annotation->value;
                if(!is_array($roles))
                    $roles = array($roles);
                foreach ($roles as $role) {
                    $role = strtoupper($role);
                    if(strpos($role,$this->rolePrefix)!==0)
                        $role = $this->rolePrefix.$role;
                    $authorities[] = $role;
                }
            } elseif($annotation instanceof FullyAuthenticated) {
                $authorities[] = AuthenticatedVoter::IS_AUTHENTICATED_FULLY;
            } elseif($annotation instanceof Authenticated) {
                $authorities[] = AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED;
            }
        }
        return $authorities;
    }

    protected function uniqueAuthorities($authorities)
    {
        return array_unique(array_values($authorities));
    }
}
