<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\LockedException as LockedExceptionInterface;

class LockedException
extends AuthenticationException
implements LockedExceptionInterface
{}
