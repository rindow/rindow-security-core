<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\AccountExpiredException as AccountExpiredExceptionInterface;

class AccountExpiredException
extends AuthenticationException
implements AccountExpiredExceptionInterface
{}
