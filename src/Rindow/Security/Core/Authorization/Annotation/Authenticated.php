<?php
namespace Rindow\Security\Core\Authorization\Annotation;

use Rindow\Stdlib\Entity\AbstractPropertyAccess;

/**
* @Annotation
* @Target({ TYPE,METHOD })
*/
class Authenticated extends AbstractPropertyAccess
{
}
