<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Interop\Lenient\Security\Authentication\UserDetails\UserDetailsManager;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Security\Core\Authentication\Exception;
use Rindow\Database\Dao\Sql\TableTemplate;
use Rindow\Database\Dao\Exception\RuntimeException as DatabaseRuntimeException;
use Rindow\Database\Dao\Exception\ExceptionInterface as DatabaseErrorCode;

class SqlUserDetailsManager implements UserDetailsManager
{
    protected $dataSource;
    protected $tableTemplate;
    protected $repositoryName = 'rindow_authusers';
    protected $authoritiesRepositoryName = 'rindow_authorities';
    protected $transactionBoundary;
    protected $maxPasswordAge;

    public function __construct($dataSource=null,$transactionBoundary=null,$repositoryName=null,$authoritiesRepositoryName=null)
    {
        if($dataSource)
            $this->setDataSource($dataSource);
        if($transactionBoundary)
            $this->setTransactionBoundary($transactionBoundary);
        if($repositoryName)
            $this->setRepositoryName($repositoryName);
        if($authoritiesRepositoryName)
            $this->setAuthoritiesRepositoryName($authoritiesRepositoryName);
    }

    public function setDataSource($dataSource)
    {
        $this->dataSource = $dataSource;
    }

    public function setRepositoryName($repositoryName)
    {
        $this->repositoryName = $repositoryName;
    }

    public function setAuthoritiesRepositoryName($authoritiesRepositoryName)
    {
        $this->authoritiesRepositoryName = $authoritiesRepositoryName;
    }

    public function setTransactionBoundary($transactionBoundary)
    {
        $this->transactionBoundary = $transactionBoundary;
    }

    public function setMaxPasswordAge($maxPasswordAge)
    {
        $this->maxPasswordAge = $maxPasswordAge;
    }

    protected function getTableTemplate()
    {
        if($this->tableTemplate)
            return $this->tableTemplate;
        $this->tableTemplate = new TableTemplate($this->dataSource);
        return $this->tableTemplate;
    }

    protected function findOne($table,array $filter)
    {
        $results = $this->getTableTemplate()->find($table,$filter,null,1);
        $result = null;
        foreach ($results as $row) {
            $result = $row;
        }
        return $result;
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
        if(isset($info['accountExpirationDate'])) {
            if($info['accountExpirationDate'] < $now)
                $accountNonExpired = false;
        }
        if($this->maxPasswordAge && isset($info['lastPasswordChangeDate'])) {
            if($info['lastPasswordChangeDate'] < $now+($this->maxPasswordAge*86400)) // 86400=3600sec*24hour
                $credentialsNonExpired = false;
        }
        if(isset($info['lockExpirationDate'])) {
            if($info['lockExpirationDate'] < 0 ||
               $info['lockExpirationDate'] < $now)
                $accountNonLocked = false;
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
            $id,$disabled,$accountNonExpired,
            $credentialsNonExpired,$accountNonLocked,$info)
    {
        $user = new User(
            $username,$password,$authorities,
            $id,$disabled,$accountNonExpired,
            $credentialsNonExpired,$accountNonLocked,$info);
        return $user;
    }

    public function loadUserByUsername($username)
    {
        return $this->loadUserBy('username',$username);
    }

    public function loadUser($id)
    {
        return $this->loadUserBy('id',$id);
    }

    public function loadUserBy($keyName,$key)
    {
        $values = $this->findOne($this->repositoryName,array($keyName=>$key));
        if(!isset($values['username']))
            throw new Exception\UsernameNotFoundException($keyName.':'.$key);
        $values['authorities'] = $this->loadUserAuthorities($values);
        return $this->mapUser($values);
    }

    protected function loadUserAuthorities($values)
    {
        $results = $this->getTableTemplate()->find($this->authoritiesRepositoryName,array('userid'=>$values['id']));
        $authorities = array();
        foreach($results as $authority) {
            $authorities[] = $authority['authority'];
        }
        return $authorities;
    }

    protected function userToArray(/*UserDetails*/ $user)
    {
        $values = array();
        $values['username'] = $user->getUsername();
        $values['password'] = $user->getPassword();
        $values['disabled'] = $user->isEnabled() ? 0 : 1;
        $values = $this->complementAuthoritiesToArray($user,$values);
        $values = array_merge($values,$user->getProperties());
        return $values;
    }

    protected function complementAuthoritiesToArray($user,$values)
    {
        return $values;
    }

    public function createUser(/*UserDetails*/ $user)
    {
        if(!$this->transactionBoundary)
            return $this->doCreateUser($user);
        return $this->transactionBoundary->required(function($manager,$user){
            return $manager->doCreateUser($user);
        },array($this,$user));
    }

    public function updateUser(/*UserDetails*/ $user)
    {
        if(!$this->transactionBoundary)
            return $this->doUpdateUser($user);
        return $this->transactionBoundary->required(function($manager,$user){
            return $manager->doUpdateUser($user);
        },array($this,$user));
    }

    public function deleteUser(/*String*/ $username)
    {
        if(!$this->transactionBoundary)
            return $this->doDeleteUser($username);
        return $this->transactionBoundary->required(function($manager,$username){
            return $manager->doDeleteUser($username);
        },array($this,$username));
    }

    public function doCreateUser(/*UserDetails*/ $user)
    {
        try {
            $values = $this->userToArray($user);
            $this->getTableTemplate()->insert($this->repositoryName,$values);
            $id = $this->getTableTemplate()->getLastInsertId($this->repositoryName,'id');
            $this->createAuthorities($id,$user);
            $user->setId($id);
        } catch(DatabaseRuntimeException $e) {
            if($e->getCode()===DatabaseErrorCode::ALREADY_EXISTS) {
                throw new Exception\DuplicateUsernameException('duplicate username:'.$user->getUsername());
            }
            throw $e;
        }
    }

    public function doUpdateUser(/*UserDetails*/ $user)
    {
        $values = $this->userToArray($user);
        if($user->getId()!==null) {
            $keyName = 'id';
            $values['id'] = $user->getId();
        } else {
            $keyName = 'username';
        }
        $check = $this->findOne($this->repositoryName,array($keyName=>$values[$keyName]));
        if(!$check)
            throw new Exception\InvalidArgumentException('unknown username or id:'.$user->getUsername().'('.$user->getId().')');
        if(!isset($values['id']))
            $values['id'] = $check['id'];
        $filter = array($keyName=>$values[$keyName]);
        $data = $values;
        unset($data[$keyName]);
        $check = $this->getTableTemplate()->update($this->repositoryName,$filter,$data);
        $this->updateAuthorities($values['id'],$user);
    }

    public function userExists(/*String*/ $username)
    {
        $check = $this->getTableTemplate()->count($this->repositoryName,array('username'=>$username));
        return $check ? true : false;
    }

    public function doDeleteUser(/*String*/ $username)
    {
        $check = $this->findOne($this->repositoryName,array('username'=>$username));
        if(!$check)
            return;
        $this->getTableTemplate()->delete($this->repositoryName,array('username'=>$username));
        $this->deleteAuthorities($check['id']);
    }

    protected function createAuthorities($userid,$user)
    {
        $table = $this->getTableTemplate();
        foreach ($user->getAuthorities() as $authority) {
            $values = array('userid'=>$userid,'authority'=>$authority);
            $table->insert($this->authoritiesRepositoryName,$values);
        }
    }

    protected function deleteAuthorities($userid)
    {
        $table = $this->getTableTemplate();
        $table->delete($this->authoritiesRepositoryName,array('userid'=>$userid));
    }

    protected function updateAuthorities($userid,$user)
    {
        $this->deleteAuthorities($userid,$user);
        $this->createAuthorities($userid,$user);
    }
}