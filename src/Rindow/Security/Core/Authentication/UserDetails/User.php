<?php
namespace Rindow\Security\Core\Authentication\UserDetails;

use Interop\Lenient\Security\Authentication\UserDetails\CredentialsContainer;
use Interop\Lenient\Security\Authentication\UserDetails\UserDetails;
use Rindow\Security\Core\Authentication\Exception;
use Serializable;

class User implements UserDetails,CredentialsContainer,Serializable
{
    protected $id;
    protected $username;
    protected $password;
    protected $authorities = array();
    protected $enabled = true;
    protected $accountNonExpired = true;
    protected $credentialsNonExpired = true;
    protected $accountNonLocked = true;
    protected $properties = array();
    protected $policy = array();

    public function __construct(
        $username,$password,array $authorities,
        $id=null,$enabled=null,
        $accountNonExpired=null,
        $credentialsNonExpired=null,
        $accountNonLocked=null,
        array $properties=null)
    {
        if(empty($username) || $password===null)
            throw new Exception\InvalidArgumentException('Cannot pass null or empty values to constructor');

        $this->username = $username;
        $this->password = $password;
        $this->authorities = $authorities;
        $this->id = $id;
        if($enabled!==null)
            $this->enabled = $enabled;
        if($accountNonExpired!==null)
            $this->accountNonExpired = $accountNonExpired;
        if($accountNonLocked!==null)
            $this->accountNonLocked = $accountNonLocked;
        if($credentialsNonExpired!==null)
            $this->credentialsNonExpired = $credentialsNonExpired;
        if($properties!=null)
            $this->properties = $properties;
    }

    public function getId()
    {
        return $this->id;
    }

    public function setId($id)
    {
        if($this->id!==null)
            throw new Exception\DomainException('This user already has an Id.');
            
        return $this->id = $id;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function getAuthorities()
    {
        return $this->authorities;
    }

    public function setProperty($name,$value)
    {
        if(in_array($name,array(
            'id','username','password','authorities','enabled',
            'accountNonExpired','accountNonLocked','credentialsNonExpired')))
            throw new Exception\DomainException('Invalid property name');
            
        $this->properties[$name] = $value;
    }

    public function unsetProperty($name)
    {
        unset($this->properties[$name]);
    }

    public function isPropertyExists($name)
    {
        return array_key_exists($name, $this->properties);
    }

    public function getProperty($name)
    {
        if(!$this->isPropertyExists($name))
            throw new Exception\DomainException('a property is not found: '.$name);
        return $this->properties[$name];
    }

    public function getPropertyNames()
    {
        return array_keys($this->properties);
    }

    public function getProperties()
    {
        return $this->properties;
    }

    public function isAccountNonExpired()
    {
        return $this->accountNonExpired ? true : false;
    }

    public function isAccountNonLocked()
    {
        return $this->accountNonLocked;
    }

    public function isCredentialsNonExpired()
    {
        return $this->credentialsNonExpired ? true : false;
    }

    public function isEnabled()
    {
        return $this->enabled;
    }

    public function eraseCredentials()
    {
        $this->password = null;
    }

    public function serialize()
    {
        $array = array(
            $this->id,
            $this->username,
            $this->password,
            $this->authorities,
            $this->enabled,
            $this->accountNonExpired,
            $this->accountNonLocked,
            $this->credentialsNonExpired
        );
        return serialize($array);
    }

    public function unserialize($serialized)
    {
        list(
            $this->id,
            $this->username,
            $this->password,
            $this->authorities,
            $this->enabled,
            $this->accountNonExpired,
            $this->accountNonLocked,
            $this->credentialsNonExpired
        ) = unserialize($serialized);
    }
}