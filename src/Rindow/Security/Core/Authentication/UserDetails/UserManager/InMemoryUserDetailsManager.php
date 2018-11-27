<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsManager;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Security\Core\Authentication\Exception;

class InMemoryUserDetailsManager implements UserDetailsManager
{
    protected $users = array();

    public function __construct(array $config = null)
    {
        $this->setConfig($config);
    }

    public function setConfig(array $config=null)
    {
        if(!$config)
            return;
        foreach ($config as $username => $info) {
            $user = $this->arrayToUser($username,$info);
            $this->createUser($user);
        }
    }

    protected function arrayToUser($username,array $info)
    {
        $authorities=array();
        $password=$id=$enabled=$accountNonExpired=$credentialsNonExpired=$accountNonLocked=null;
        if(isset($info['password']))
            $password = $info['password'];
        if(isset($info['roles'])) {
            foreach($info['roles'] as $role) {
                $authorities[] = 'ROLE_'.$role;
            }
        }
        if(isset($info['enabled']))
            $enabled = $info['enabled'];
        if(isset($info['id']))
            $id = $info['id'];
        if(isset($info['accountNonExpired']))
            $accountNonExpired = $info['accountNonExpired'];
        if(isset($info['credentialsNonExpired']))
            $credentialsNonExpired = $info['credentialsNonExpired'];
        if(isset($info['accountNonLocked']))
            $accountNonLocked = $info['accountNonLocked'];
        $user = new User($username,$password,$authorities,$id,$enabled,$accountNonExpired,$credentialsNonExpired,$accountNonLocked);
        return $user;
    }

    public function loadUserByUsername($username)
    {
        if(!array_key_exists($username, $this->users))
            throw new Exception\UsernameNotFoundException($username);
        return $this->users[$username];
    }

    public function createUser(/*UserDetails*/ $user)
    {
        $username = $user->getUsername();
        if($this->userExists($username))
            throw new Exception\InvalidArgumentException('duplicate username:'.$username);
        $this->users[$username] = $user;
    }

    public function updateUser(/*UserDetails*/ $user)
    {
        $username = $user->getUsername();
        if(!$this->userExists($username))
            throw new Exception\InvalidArgumentException('unknown username:'.$username);
        $this->users[$username] = $user;
    }

    public function userExists(/*String*/ $username)
    {
        return array_key_exists($username, $this->users);
    }

    public function deleteUser(/*String*/ $username)
    {
        unset($this->users[$username]);
    }
}