<?php
namespace Rindow\Security\Core\Authorization\Annotation;

use Rindow\Stdlib\Entity\AbstractPropertyAccess;

/**
* @Annotation
* @Target({ TYPE })
*/
class RunAs extends AbstractPropertyAccess
{
    /**
     * @var string role
     */
    public $value;
}
