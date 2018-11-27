<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\DuplicateUsernameException as DuplicateUsernameExceptionInterface;

class DuplicateUsernameException
extends InvalidArgumentException
implements DuplicateUsernameExceptionInterface
{}
