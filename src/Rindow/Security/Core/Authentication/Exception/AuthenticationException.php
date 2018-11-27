<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\AuthenticationException as AuthenticationExceptionInterface;

class AuthenticationException
extends RuntimeException
implements AuthenticationExceptionInterface
{}
