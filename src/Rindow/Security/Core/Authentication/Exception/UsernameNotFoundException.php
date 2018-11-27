<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\UsernameNotFoundException as UsernameNotFoundExceptionInterface;

class UsernameNotFoundException
extends RuntimeException
implements UsernameNotFoundExceptionInterface
{}
