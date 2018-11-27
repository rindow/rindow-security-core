<?php
namespace Rindow\Security\Core\Authorization\Annotation;

use Rindow\Stdlib\Entity\AbstractPropertyAccess;

/**
* @Annotation
* @Target({ TYPE })
*/
class DeclaresRoles extends AbstractPropertyAccess
{
    /**
     * @var string or Array<String> roles
     */
    public $value;
}
