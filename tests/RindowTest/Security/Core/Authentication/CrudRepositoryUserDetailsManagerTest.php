<?php
namespace RindowTest\Security\Core\Authentication\CrudRepositoryUserDetailsManagerTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\CrudRepositoryUserDetailsManager;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\UserDetailsSqlRepository;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Stdlib\Dict;

use Rindow\Transaction\Support\TransactionBoundary;
use Rindow\Database\Dao\Repository\DataMapper;
use Rindow\Database\Dao\Sql\TableTemplate;
use Rindow\Database\Pdo\DataSource;

use Rindow\Container\ModuleManager;

class Test extends TestCase
{
    static $RINDOW_TEST_DATA;
    public static $skip = false;
    public static function setUpBeforeClass()
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::$skip = 'pdo_sqlite extension not loaded';
            return;
        }
        self::$RINDOW_TEST_DATA = __DIR__.'/../../../../data';
        //try {
            $dsn = "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite";
            $username = null;
            $password = null;
            $options  = array();
            $client = new \PDO($dsn, $username, $password, $options);
        //} catch(\Exception $e) {
        //    self::$skip = $e->getMessage();
        //    return;
        //}
    }

    public static function tearDownAfterClass()
    {
        if(self::$skip)
            return;
        $dsn = "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite";
        $username = null;
        $password = null;
        $options  = array();
        //$client = new \PDO($dsn, $username, $password, $options);
        //$client->exec("DROP TABLE IF EXISTS rindow_authusers");
    }

    public function setUp()
    {
        if(self::$skip) {
            $this->markTestSkipped(self::$skip);
            return;
        }
        $dsn = "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite";
        $username = null;
        $password = null;
        $options  = array();
        $client = new \PDO($dsn, $username, $password, $options);
        $client->exec("DROP TABLE IF EXISTS rindow_authusers");
        $client->exec("CREATE TABLE rindow_authusers (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,disabled INTEGER,accountExpirationDate INTEGER,lastPasswordChangeDate INTEGER,lockExpirationDate INTEGER)
");
        $client->exec("DROP TABLE IF EXISTS rindow_authorities");
        $client->exec("CREATE TABLE rindow_authorities (userid INTEGER,authority TEXT)");
        $client->exec("CREATE INDEX rindow_authorities_userid ON rindow_authorities (userid)");
        $client->exec("CREATE UNIQUE INDEX rindow_authorities_unique ON rindow_authorities (userid,authority)");
    }

    public function getConfig()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\\Aop\\Module'=>true,
                    'Rindow\\Database\\Dao\\Sql\\Module' => true,
                    'Rindow\\Transaction\\Local\\Module' => true,
                    'Rindow\\Database\\Pdo\\LocalTxModule' => true,
                    'Rindow\\Security\\Core\\Module' => true,
                ),
                'enableCache' => false,
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsRepository'=>
                        'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsSqlRepository',
                ),
                'components' => array(
                ),
            ),
            'database' => array(
                'connections' => array(
                    'default' => array(
                        'dsn' => "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite",
                    ),
                ),
            ),
            'security' => array(
                'authentication' => array(
                    'default' => array(
                        'maxPasswordAge' => 1, // 1 days
                    ),
                ),
            ),
        );
        return $config;
    }

    public function getDataStoreUserDetailsManager()
    {
        $mm = new ModuleManager($this->getConfig());
        return $mm->getServiceLocator()->get('Rindow\\Security\\Core\\Authentication\\DefaultCrudRepositoryUserDetailsManager');
    }

    public function testLoadingDefaultSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN','ROLE_USER')));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\UserDetails\User',$user);
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN','ROLE_USER'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testLoadingDisabledSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'disabled'=>1,'accountExpirationDate'=>1,'lastPasswordChangeDate'=>1,'lockExpirationDate'=>time()+1000));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertFalse($user->isAccountNonExpired());
        $this->assertFalse($user->isAccountNonLocked());
        $this->assertFalse($user->isCredentialsNonExpired());
        $this->assertFalse($user->isEnabled());
    }

    public function testAccountNonExpiredWithExpiredDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'accountExpirationDate'=>time()-1));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertFalse($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testAccountNonExpiredWithZero()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'accountExpirationDate'=>0));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testAccountNonExpiredWithNonExpiredDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'accountExpirationDate'=>time()+1000));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testAccountNonLockedUntilExpireDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lockExpirationDate'=>(time()+1000)));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertFalse($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testAccountNonLockedWithUnlockedDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lockExpirationDate'=>(time()-10)));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testCredentialsNonExpiredWithExpiredDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lastPasswordChangeDate'=>time()-86400-1));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertFalse($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testCredentialsNonExpiredWithNonExpiredDate()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lastPasswordChangeDate'=>time()));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testDisabled()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'disabled'=>1));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertFalse($user->isEnabled());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\UsernameNotFoundException
     * @expectedExceptionMessage foo
     */
    public function testUsernameNotFoundException()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->loadUserByUsername('foo');
    }

    public function testUpdateSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());
        $user2 = new User('foo2','fooPass2',array('ROLE_ADMIN'));
        $manager->createUser($user2);
        $this->assertEquals(2,$user2->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());

        $user = new User('foo','boopass',array('ROLE_USER'));
        $manager->updateUser($user);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals(1,$user->getId());
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('boopass',$user->getPassword());
        $this->assertEquals(array('ROLE_USER'),$user->getAuthorities());

        $user = new User('boo','boopass2',array('ROLE_OTHER'),$user->getId());
        $manager->updateUser($user);
        $user = $manager->loadUserByUsername('boo');
        $this->assertEquals(1,$user->getId());
        $this->assertEquals('boo',$user->getUsername());
        $this->assertEquals('boopass2',$user->getPassword());
        $this->assertEquals(array('ROLE_OTHER'),$user->getAuthorities());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage unknown username or id:boo()
     */
    public function testUpdateFailed()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());

        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->updateUser($user);
    }

    public function testCreateSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $this->assertFalse($manager->userExists('boo'));
        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->createUser($user);
        $this->assertEquals(2,$user->getId());
        $this->assertTrue($manager->userExists('boo'));

        $user = $manager->loadUserByUsername('boo');
        $this->assertEquals('boo',$user->getUsername());
        $this->assertEquals('boopass',$user->getPassword());
        $this->assertEquals(array('ROLE_USER'),$user->getAuthorities());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\DuplicateUsernameException
     * @expectedExceptionMessage duplicate username:boo
     */
    public function testCreateFailed()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('boo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->createUser($user);
    }

    public function testDeleteSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $this->assertTrue($manager->userExists('foo'));
        $manager->deleteUser('foo');
        $this->assertFalse($manager->userExists('foo'));

        $this->assertFalse($manager->userExists('boo'));
        $manager->deleteUser('boo');
        $this->assertFalse($manager->userExists('boo'));
    }

    public function testLoadUser()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());

        $user2 = $manager->loadUser($user->getId());
        $this->assertEquals(1,$user2->getId());
        $this->assertEquals('foo',$user2->getUsername());
        $this->assertEquals('fooPass',$user2->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user2->getAuthorities());
    }
/*
    public function testOnModule()
    {
        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\\Security\\Core\\Module' => true,
                    'Rindow\\Database\\Pdo\\LocalTxModule' => true,
                ),
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService' => 'Rindow\\Security\\Core\\Authentication\\DefaultCrudRepositoryUserDetailsManager',
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsRepository' => 'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsSqlRepository',
                    'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManagerDataSource' => 'Rindow\\Database\\Pdo\\Transaction\\DefaultDataSource',
                ),
            ),
            'security' => array(
                'authentication' => array(
                    'default' => array(
                        'repositoryName' => 'rindow_authusers',
                    ),
                ),
            ),
            'database'=>array(
                'connections'=>array(
                    'default' => array(
                        'dsn' => "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite",
                    ),
                ),
            ),
        );
        $mm = new ModuleManager($config);
        $manager = $mm->getServiceLocator()->get('Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService');
        $user = new User('foo','fooPass',array('ROLE_ADMIN','ROLE_USER'));
        $manager->createUser($user);
        $this->assertEquals(1,$user->getId());
    }
*/
}