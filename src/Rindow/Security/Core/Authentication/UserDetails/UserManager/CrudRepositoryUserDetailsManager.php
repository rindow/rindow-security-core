<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Rindow\Security\Core\Authentication\UserDetails\User;

class CrudRepositoryUserDetailsManager extends AbstractCrudRepositoryUserDetailsManager
{
    protected $maxPasswordAge;

    public function setMaxPasswordAge($maxPasswordAge)
    {
        $this->maxPasswordAge = $maxPasswordAge;
    }

    public function mapUser($info)
    {
        if(!is_array($info))
            throw new Exception\InvalidArgumentException('mapping data must be array.');
        $authorities=array();
        $password=$id=null;
        $enabled=$accountNonExpired=$accountNonLocked=$credentialsNonExpired=true;
        $now = time();
        if(!isset($info['username']))
            throw new Exception\InvalidArgumentException('User requires "username".');
        $username = $info['username'];
        if(isset($info['password']))
            $password = $info['password'];
        if(isset($info['authorities']))
            $authorities = $info['authorities'];
        if(isset($info['id']))
            $id = $info['id'];
        if(isset($info['disabled']) && $info['disabled'])
            $enabled = false;
        if(isset($info['accountExpirationDate']) && $info['accountExpirationDate']) {
            if($info['accountExpirationDate'] < $now)
                $accountNonExpired = false;
        }
        if($this->maxPasswordAge && isset($info['lastPasswordChangeDate']) && $info['lastPasswordChangeDate']) {
            if($info['lastPasswordChangeDate']+($this->maxPasswordAge*86400) < $now) // 86400=3600sec*24hour
                $credentialsNonExpired = false;
        }
        if(isset($info['lockExpirationDate']) && $info['lockExpirationDate']) {
            if($now < $info['lockExpirationDate'] ) {
                $accountNonLocked = false;
            }
        }
        unset($info['username']);
        unset($info['password']);
        unset($info['authorities']);
        $user = $this->doCreateUserEntity(
            $username,$password,$authorities,
            $id,$enabled,$accountNonExpired,
            $credentialsNonExpired,$accountNonLocked,$info);
        return $user;
    }

    protected function doCreateUserEntity(
            $username,$password,$authorities,
            $id,$enabled,$accountNonExpired,
            $credentialsNonExpired,$accountNonLocked,$info)
    {
        $user = new User(
            $username,$password,$authorities,
            $id,$enabled,$accountNonExpired,
            $credentialsNonExpired,$accountNonLocked,$info);
        return $user;
    }

    public function demapUser(/*UserDetails*/ $user)
    {
        $values = array();
        $values['username'] = $user->getUsername();
        $values['password'] = $user->getPassword();
        $values['disabled'] = $user->isEnabled() ? 0 : 1;
        $values = $this->complementAuthoritiesToArray($user,$values);
        $values = array_merge($values,$user->getProperties());
        return $values;
    }

    protected function loadUserAuthorities($values)
    {
        return $values['authorities'];
    }

    protected function complementAuthoritiesToArray($user,$values)
    {
        $values['authorities'] = $user->getAuthorities();
        return $values;
    }

    protected function createAuthorities($userid,$user)
    {
    }

    protected function updateAuthorities($userid,$user)
    {
    }

    protected function deleteAuthorities($userid)
    {
    }
}