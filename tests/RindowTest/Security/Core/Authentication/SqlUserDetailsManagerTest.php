<?php
namespace RindowTest\Security\Core\Authentication\SqlUserDetailsManagerTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\SqlUserDetailsManager;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Stdlib\Dict;

use Rindow\Transaction\Support\TransactionBoundary;
use Rindow\Database\Pdo\DataSource;
use Rindow\Container\ModuleManager;
use Rindow\Security\Core\Authentication\Exception\DuplicateUsernameException;


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
        //$client->exec("DROP TABLE IF EXISTS rindow_authaccounts");
    }

    public function getDsn()
    {
        $dsn = "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite";
        return $dsn;
    }

    public function getPdo()
    {
        $username = null;
        $password = null;
        $options  = array();
        $client = new \PDO($this->getDsn(), $username, $password, $options);
        return $client;
    }

    public function setUp()
    {
        if(self::$skip) {
            $this->markTestSkipped(self::$skip);
            return;
        }
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );
        \Rindow\Stdlib\Cache\CacheFactory::clearCache();
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );

        $client = $this->getPdo();
        $client->exec("DROP TABLE IF EXISTS rindow_authusers");
        $client->exec("CREATE TABLE rindow_authusers (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,disabled INTEGER,accountExpirationDate INTEGER,lastPasswordChangeDate INTEGER,lockExpirationDate INTEGER)
");
        $client->exec("DROP TABLE IF EXISTS rindow_authorities");
        $client->exec("CREATE TABLE rindow_authorities (userid INTEGER,authority TEXT)");
        $client->exec("CREATE INDEX rindow_authorities_userid ON rindow_authorities (userid)");
        $client->exec("CREATE UNIQUE INDEX rindow_authorities_unique ON rindow_authorities (userid,authority)");
    }

    public function getDataStoreUserDetailsManager($transactionManager=null)
    {
        $config = array(
            'dsn' => $this->getDsn(),
        );
        $dataSource = new DataSource($config);
        $transactionBoundary = new TransactionBoundary();
        $transactionBoundary->setWithoutTransactionManagement(true);
        $repositoryName = 'rindow_authusers';
        $authoritiesRepositoryName = 'rindow_authorities';
        $manager = new SqlUserDetailsManager($dataSource,$transactionBoundary,$repositoryName,$authoritiesRepositoryName);
        $manager->setMaxPasswordAge(10);
        return $manager;
    }

    public function testLoadingDefaultSuccess()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = new User('foo','fooPass',array('ROLE_ADMIN','ROLE_USER'));
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
            'disabled'=>1,'accountExpirationDate'=>1,'lastPasswordChangeDate'=>1,'lockExpirationDate'=>-1));

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

    public function testAccountNonExpired()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'accountExpirationDate'=>1));
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

    public function testAccountNonLocked()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lockExpirationDate'=>-1));
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

    public function testCredentialsNonExpired()
    {
        $manager = $this->getDataStoreUserDetailsManager();
        $user = $manager->mapUser(array('username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN'),
            'lastPasswordChangeDate'=>1));
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

        $user = new User('foo','fooPass',array('ROLE_ADMIN'));
        $manager->createUser($user);
        $this->assertTrue(true);
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

    public function testOnTransactionCommit()
    {
        $pdo = $this->getPdo();
        $pdo->exec("DROP TABLE IF EXISTS testdb");
        $pdo->exec("CREATE TABLE testdb ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
        unset($pdo);

        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\\Aop\\Module'=>true,
                    'Rindow\\Transaction\\Local\\Module'=>true,
                    'Rindow\\Database\\Dao\\Sql\\Module'=>true,
                    'Rindow\\Database\\Pdo\\LocalTxModule'=>true,
                    'Rindow\\Security\\Core\\Module' => true,
                ),
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService'   => 'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManager',
                ),
                'components' => array(
                    __NAMESPACE__.'\TestDbRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'testdb'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthusersRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authusers'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthoritiesRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authorities'),
                        ),
                    ),
                ),
            ),
            'database' => array(
                'connections'=>array(
                    'default' => array(
                        'dsn' => $this->getDsn(),
                    ),
                ),
            ),
        );
        $mm = new ModuleManager($config);
        $services   = $mm->getServiceLocator();
        $users   = $services->get('Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService');
        $tx      = $services->get('Rindow\\Database\\Pdo\\Transaction\\DefaultTransactionBoundary');
        $this->assertFalse($tx->getWithoutTransactionManagement());

        $this->assertFalse($users->userExists('foo'));
        $tx->required(function() use ($users,$services) {
            $user = new User('foo','fooPass',array('ROLE_ADMIN','ROLE_USER'));
            $users->createUser($user);
            $services->get(__NAMESPACE__.'\TestDbRepository')->save(array('name'=>'somedata'));
        });
        $this->assertTrue($users->userExists('foo'));
        $data = $services->get(__NAMESPACE__.'\TestDbRepository')->findById(1);
        $this->assertEquals(array('id'=>1,'name'=>'somedata'),$data);
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthusersRepository')->findAll() as $data) {
            $count++;
        }
        $this->assertEquals(1,$count);
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthoritiesRepository')->findAll() as $data) {
            if($data['authority']=='ROLE_USER')
                $this->assertEquals(array('userid'=>1,'authority'=>'ROLE_USER'),$data);
            elseif($data['authority']=='ROLE_ADMIN')
                $this->assertEquals(array('userid'=>1,'authority'=>'ROLE_ADMIN'),$data);
            else
                throw new \Exception("Error Processing Request", 1);
            $count++;
        }
        $this->assertEquals(2,$count);
    }

    public function testOnTransactionRollback()
    {
        $pdo = $this->getPdo();
        $pdo->exec("DROP TABLE IF EXISTS testdb");
        $pdo->exec("CREATE TABLE testdb ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
        unset($pdo);

        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\\Aop\\Module'=>true,
                    'Rindow\\Transaction\\Local\\Module'=>true,
                    'Rindow\\Database\\Dao\\Sql\\Module'=>true,
                    'Rindow\\Database\\Pdo\\LocalTxModule'=>true,
                    'Rindow\\Security\\Core\\Module' => true,
                    //'Rindow\\Module\\Monolog\\Module' => true,
                ),
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService'   => 'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManager',
                ),
                'components' => array(
                    __NAMESPACE__.'\TestDbRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'testdb'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthusersRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authusers'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthoritiesRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authorities'),
                        ),
                    ),
                    'Rindow\\Database\\Pdo\\Transaction\\DefaultDataSource'=>array(
                        'properties'=>array(
                            // === for debug options ===
                            //'debug' => array('value'=>true),
                            //'logger' => array('ref'=>'Logger'),
                        ),
                    ),
                    'Rindow\\Database\\Pdo\\Transaction\\DefaultTransactionManager' => array(
                        'properties'=>array(
                            // === for debug options ===
                            //'debug' => array('value'=>true),
                            //'logger' => array('ref'=>'Logger'),
                        ),
                    ),
                ),
            ),
            'database' => array(
                'connections'=>array(
                    'default' => array(
                        'dsn' => $this->getDsn(),
                    ),
                ),
            ),
            // === for debug options ===
            'monolog' => array(
                'handlers' => array(
                    'default' => array(
                        'path'  => __DIR__.'/../../../../log/debug.log',
                    ),
                ),
            ),
        );
        $mm = new ModuleManager($config);
        $services = $mm->getServiceLocator();
        $users   = $services->get('Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService');
        $tx      = $services->get('Rindow\\Database\\Pdo\\Transaction\\DefaultTransactionBoundary');
        $this->assertFalse($tx->getWithoutTransactionManagement());

        // rollbacked users
        $this->assertFalse($users->userExists('foo'));
        try {
            $tx->required(function() use ($users,$services) {
                $user = new User('foo','fooPass',array('ROLE_ADMIN','ROLE_USER'));
                $users->createUser($user);
                $services->get(__NAMESPACE__.'\TestDbRepository')->save(array('name'=>'somedata'));
                throw new \Exception("Error Processing Request", 1);
            });
        } catch(\Exception $e) {
            if(get_class($e)!='Exception')
                throw $e;
        }
        $this->assertFalse($users->userExists('foo'));
        $data = $services->get(__NAMESPACE__.'\TestDbRepository')->findById(1);
        $this->assertTrue(empty($data));
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthusersRepository')->findAll() as $data) {
            $count++;
        }
        // rollbacked users
        $this->assertEquals(0,$count);
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthoritiesRepository')->findAll() as $data) {
            if($data['authority']=='ROLE_USER')
                $this->assertEquals(array('userid'=>1,'authority'=>'ROLE_USER'),$data);
            elseif($data['authority']=='ROLE_ADMIN')
                $this->assertEquals(array('userid'=>1,'authority'=>'ROLE_ADMIN'),$data);
            else
                throw new \Exception("Error Processing Request", 1);
            $count++;
        }
        // rollbacked users
        $this->assertEquals(0,$count);
    }

    public function testOnTransactionAuthorityDuplicateError()
    {
        $pdo = $this->getPdo();
        $pdo->exec("INSERT INTO rindow_authorities ( userid, authority) VALUES (1,'ROLE_USER')");
        unset($pdo);

        $config = array(
            'module_manager' => array(
                'modules' => array(
                    'Rindow\\Aop\\Module'=>true,
                    'Rindow\\Transaction\\Local\\Module'=>true,
                    'Rindow\\Database\\Dao\\Sql\\Module'=>true,
                    'Rindow\\Database\\Pdo\\LocalTxModule'=>true,
                    'Rindow\\Security\\Core\\Module' => true,
                    //'Rindow\\Module\\Monolog\\Module' => true,
                ),
            ),
            'container' => array(
                'aliases' => array(
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService'   => 'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManager',
                ),
                'components' => array(
                    __NAMESPACE__.'\TestDbRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'testdb'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthusersRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authusers'),
                        ),
                    ),
                    __NAMESPACE__.'\AuthoritiesRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'properties'=>array(
                            'tableName'=>array('value'=>'rindow_authorities'),
                        ),
                    ),
                    'Rindow\\Database\\Pdo\\Transaction\\DefaultDataSource'=>array(
                        'properties'=>array(
                            // === for debug options ===
                            //'debug' => array('value'=>true),
                            //'logger' => array('ref'=>'Logger'),
                        ),
                    ),
                    'Rindow\\Database\\Pdo\\Transaction\\DefaultTransactionManager' => array(
                        'properties'=>array(
                            // === for debug options ===
                            //'debug' => array('value'=>true),
                            //'logger' => array('ref'=>'Logger'),
                        ),
                    ),
                ),
            ),
            'database' => array(
                'connections'=>array(
                    'default' => array(
                        'dsn' => $this->getDsn(),
                    ),
                ),
            ),
            // === for debug options ===
            'monolog' => array(
                'handlers' => array(
                    'default' => array(
                        'path'  => __DIR__.'/../../../../log/debug.log',
                    ),
                ),
            ),
        );
        $mm = new ModuleManager($config);
        $services = $mm->getServiceLocator();
        $users   = $services->get('Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService');
        $tx      = $services->get('Rindow\\Database\\Pdo\\Transaction\\DefaultTransactionBoundary');
        $this->assertFalse($tx->getWithoutTransactionManagement());

        $this->assertFalse($users->userExists('foo'));
        $catchDup = false;
        try {
            $tx->required(function() use ($users,$services) {
                $user = new User('foo','fooPass',array('ROLE_ADMIN','ROLE_USER'));
                $users->createUser($user);
                throw new \Exception("Error Processing Request", 1);
            });
        } catch(DuplicateUsernameException $e) {
            $catchDup = true;
        }
        $this->assertTrue($catchDup);
        $this->assertFalse($users->userExists('foo'));
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthusersRepository')->findAll() as $data) {
            $count++;
        }
        $this->assertEquals(0,$count);
        $count=0;
        foreach($services->get(__NAMESPACE__.'\AuthoritiesRepository')->findAll() as $data) {
            $this->assertEquals(array('userid'=>1,'authority'=>'ROLE_USER'),$data);
            $count++;
        }
        $this->assertEquals(1,$count);
    }
}
