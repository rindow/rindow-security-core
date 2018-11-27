<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsManager;
use Interop\Lenient\Dao\Exception\DuplicateKeyException;
use Rindow\Security\Core\Authentication\Exception;

abstract class AbstractCrudRepositoryUserDetailsManager implements UserDetailsManager
{
    abstract public function mapUser($info);
    abstract public function demapUser(/*UserDetails*/ $user);
    abstract protected function loadUserAuthorities($values);
    abstract protected function complementAuthoritiesToArray($user,$values);
    abstract protected function createAuthorities($userid,$user);
    abstract protected function updateAuthorities($userid,$user);
    abstract protected function deleteAuthorities($userid);

    protected $repository;

    public function setRepository($repository)
    {
        $this->repository = $repository;
    }

    public function getRepository()
    {
        return $this->repository;
    }

    public function loadUserByUsername($username)
    {
        return $this->loadUserBy('username',$username);
    }

    public function loadUserBy($keyName,$key)
    {
        $values = $this->getRepository()->findOne(array($keyName=>$key));
        if(!isset($values['username']))
            throw new Exception\UsernameNotFoundException($keyName.':'.$key);
        $values['authorities'] = $this->loadUserAuthorities($values);
        return $this->mapUser($values);
    }

    public function loadUser($id)
    {
        $values = $this->getRepository()->findById($id);
        if(!isset($values['username']))
            throw new Exception\UsernameNotFoundException('user:'.$id);
        $values['authorities'] = $this->loadUserAuthorities($values);
        return $this->mapUser($values);
    }

    public function createUser(/*UserDetails*/ $user)
    {
        try {
            $values = $this->demapUser($user);
            $newValues = $this->getRepository()->save($values);
            $this->createAuthorities($newValues['id'],$user);
            $user->setId($newValues['id']);
        } catch(DuplicateKeyException $e) {
            throw new Exception\DuplicateUsernameException('duplicate username:'.$user->getUsername(),0,$e);
        }
    }

    public function updateUser(/*UserDetails*/ $user)
    {
        $values = $this->demapUser($user);
        if($user->getId()!==null) {
            $keyName = 'id';
            $values['id'] = $user->getId();
        } else {
            $keyName = 'username';
        }
        $check = $this->getRepository()->findOne(array($keyName=>$values[$keyName]));
        if(!$check)
            throw new Exception\InvalidArgumentException('unknown username or id:'.$user->getUsername().'('.$user->getId().')');
        if(!isset($values['id']))
            $values['id'] = $check['id'];
        $this->getRepository()->save($values);
        $this->updateAuthorities($values['id'],$user);
    }

    public function userExists(/*String*/ $username)
    {
        $values = $this->getRepository()->findOne(array('username'=>$username));
        return isset($values['username']);
    }

    public function deleteUser(/*String*/ $username)
    {
        $check = $this->getRepository()->findOne(array('username'=>$username));
        if(!$check)
            return;
        $this->getRepository()->deleteAll(array('username'=>$username));
        $this->deleteAuthorities($check['id']);
    }
}