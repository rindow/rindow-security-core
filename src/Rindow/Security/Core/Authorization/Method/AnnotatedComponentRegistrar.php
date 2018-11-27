<?php
namespace Rindow\Security\Core\Authorization\Method;

use ReflectionClass;
use Rindow\Aop\AopPluginInterface;
use Rindow\Aop\AopManager;
use Rindow\Container\ComponentScanner;
use Rindow\Container\Container;
use Rindow\Security\Core\Authorization\Annotation\AccessControlled;
use Rindow\Security\Core\Authorization\Exception;

class AnnotatedComponentRegistrar implements AopPluginInterface
{
    const ANNOTATION_ACCESS_CONTROLLED = 'Rindow\\Security\\Core\\Authorization\\Annotation\\AccessControlled';

    protected $aopManager;
    protected $container;
    protected $annotationManager;
    protected $defaultTransactionManager;
    protected $config;
    protected $accessControlledClasses = array();

    public function __construct(
        AopManager $aopManager,
        Container $container)
    {
        $this->aopManager = $aopManager;
        $this->container = $container;
        $this->annotationManager = $container->getAnnotationManager();
    }

    public function setConfig($config)
    {
        if(isset($config['authorization']))
            $this->config = $config['authorization'];
    }

    public function attachScanner(ComponentScanner $componentScanner)
    {
        $componentScanner->attachCollect(
            self::ANNOTATION_ACCESS_CONTROLLED,
            array($this,'collectAccessControlled'));
        $componentScanner->attachCompleted(
            __CLASS__,
            array($this,'generateAdvice'));
    }

    public function collectAccessControlled($annoName,$className,$classAnnotation,ReflectionClass $classRef)
    {
        $this->accessControlledClasses[] = $className;
        $this->aopManager->addInterceptTarget($className);
    }

    public function generateAdvice()
    {
        if(count($this->accessControlledClasses)==0)
            return;
        $pointcut = '';
        foreach($this->accessControlledClasses as $className) {
            $pattern = 'execution('.$className.'::*())';
            if($pointcut=='')
                $pointcut = $pattern;
            else
                $pointcut .= '||'.$pattern;
        }
        if(!isset($this->config['advisorName']))
            throw new Exception\DomainException('The advisorName is not specified in aop configuration "aop::authorization".');
        if(!isset($this->config['adviceName']))
            throw new Exception\DomainException('The adviceName is not specified in aop configuration "aop::authorization".');
        if(!isset($this->config['adviceDefinition']))
            throw new Exception\DomainException('The adviceDefinition is not specified in aop configuration "aop::authorization".');
        $advisorName = $this->config['advisorName'];
        $adviceName  = $this->config['adviceName'];
        $adviceDefinition = $this->config['adviceDefinition'];
        $adviceDefinition['pointcut'] = $pointcut;
        $this->aopManager->addAdviceByConfig($adviceDefinition,$advisorName,$adviceName);
    }
}