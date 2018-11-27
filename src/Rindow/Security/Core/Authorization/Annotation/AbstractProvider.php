<?php
namespace Rindow\Security\Core\Authorization\Annotation;

use Rindow\Annotation\AnnotationProviderInterface;

abstract class AbstractProvider implements AnnotationProviderInterface
{
    public function getJoinPoints()
    {
        return array(
            'invoke' => array(
                AnnotationProviderInterface::EVENT_SET_FIELD,
            ),
        );
    }

    public function initalize($event)
    {
    }

    public function invoke($event)
    {
        $args = $event->getArgs();
        $annotationClassName = $args['annotationname'];
        $fieldName       = $args['fieldname'];
        $metadata = $args['metadata'];
        $value    = $args['value'];
        $location = $args['location'];

        $enum = $metadata->value;
        if(!isset($metadata->hashValue[$value]))
            throw new Exception\DomainException('a value "'.$value.'" is not allowed for the field "'.$fieldName.'" of annotation @'.$annotationClassName.' in '.$location['uri'].': '.$location['filename']);
    }
}
