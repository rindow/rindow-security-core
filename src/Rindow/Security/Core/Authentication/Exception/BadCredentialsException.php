<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\BadCredentialsException as BadCredentialsExceptionInterface;

class BadCredentialsException
extends AuthenticationException
implements BadCredentialsExceptionInterface
{}
