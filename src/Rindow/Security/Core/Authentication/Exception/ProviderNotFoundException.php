<?php
namespace Rindow\Security\Core\Authentication\Exception;

use Interop\Lenient\Security\Authentication\Exception\ProviderNotFoundException as ProviderNotFoundExceptionInterface;

class ProviderNotFoundException
extends AuthenticationException
implements ProviderNotFoundExceptionInterface
{}
