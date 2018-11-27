<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\DisabledException as DisabledExceptionInterface;

class DisabledException
extends AuthenticationException
implements DisabledExceptionInterface
{}
