<?php
namespace Rindow\Security\Core\Authentication\Exception;

interface ContainsRejectedAuthentication
{
    public function getAuthentication();
    public function setAuthentication($authentication);
}
