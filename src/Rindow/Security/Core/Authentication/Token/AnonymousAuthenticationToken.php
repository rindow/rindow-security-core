<?php
namespace Rindow\Security\Core\Authentication\Token;

use Rindow\Security\Core\Authentication\Exception;

class AnonymousAuthenticationToken extends AbstractAuthenticationToken
{
    protected $keyHash;

    public function __construct($keyHash, $principal,array $authorities=null)
    {
        parent::__construct($authorities);

        if (!$principal) {
            throw new Exception\InvalidArgumentException("principal cannot be null or empty");
        }
        if(empty($authorities)) {
            throw new Exception\InvalidArgumentException("authorities cannot be null or empty");
        }
        $this->keyHash = $keyHash;
        $this->setPrincipal($principal);
        $this->setAuthenticated(true);
    }

    public function getKeyHash()
    {
        return $this->keyHash;
    }

    public function getCredentials()
    {
        return '';
    }

    public function serialize()
    {
        return serialize(array(
            $this->keyHash,
            parent::serialize(),
        ));
    }

    public function unserialize($serialized)
    {
        list($this->keyHash, $parentSerialized) = unserialize($serialized);
        parent::unserialize($parentSerialized);
    }
}