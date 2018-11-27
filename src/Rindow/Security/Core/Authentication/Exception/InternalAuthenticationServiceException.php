<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\InternalAuthenticationServiceException as InternalAuthenticationServiceExceptionInterface;

class InternalAuthenticationServiceException
extends AuthenticationException
implements InternalAuthenticationServiceExceptionInterface
{}