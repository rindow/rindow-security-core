<?php
namespace Rindow\Security\Core\Authorization\Annotation;

use Rindow\Stdlib\Entity\AbstractPropertyAccess;

/**
* @Annotation
* @Target({ TYPE,METHOD })
*/
class RolesAllowed extends AbstractPropertyAccess
{
    /**
     * @var string or Array<String> roles
     */
    public $value;
}
