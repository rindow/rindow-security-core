<?php
namespace RindowTest\Security\Core\Authentication\UserDetailsSqlRepositoryTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\UserDetailsSqlRepository;
use Rindow\Stdlib\Dict;

use Rindow\Transaction\Support\TransactionBoundary;
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
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );
        \Rindow\Stdlib\Cache\CacheFactory::clearCache();
        usleep( RINDOW_TEST_CLEAR_CACHE_INTERVAL );
        $dsn = "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite";
        $username = null;
        $password = null;
        $options  = array();
        $client = new \PDO($dsn, $username, $password, $options);
        $client->exec("DROP TABLE IF EXISTS rindow_authusers");
        $client->exec("CREATE TABLE rindow_authusers (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,disabled INTEGER,accountExpirationDate INTEGER,lastPasswordChangeDate INTEGER,lockExpirationDate INTEGER)");
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
            ),
            'database' => array(
                'connections' => array(
                    'default' => array(
                        'dsn' => "sqlite:".self::$RINDOW_TEST_DATA."/test.db.sqlite",
                    ),
                ),
            ),
        );
        return $config;
    }

    public function getRepository()
    {
        $mm = new ModuleManager($this->getConfig());
        return $mm->getServiceLocator()->get('Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsSqlRepository');
    }

    public function testCreateAndFind()
    {
        $repository = $this->getRepository();
        $user = array(
            'username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN','ROLE_USER'));
        $user = $repository->save($user);
        $this->assertEquals(1,$user['id']);

        $user = array(
            'username'=>'foo2','password'=>'fooPass','authorities'=>array('ROLE_USER','ROLE_OPERATOR'));

        $user = $repository->save($user);
        $this->assertEquals(2,$user['id']);

        $user = $repository->findOne(array('username'=>'foo'));
        $this->assertEquals(
            array('id'=>1,'username'=>'foo','password'=>'fooPass',
                'disabled'=>null ,'accountExpirationDate'=>null ,'lastPasswordChangeDate'=>null ,'lockExpirationDate'=>null,
                'authorities'=>array('ROLE_ADMIN','ROLE_USER')),
            $user
        );

        $user = $repository->findOne(array('username'=>'foo2'));
        $this->assertEquals(
            array('id'=>2,'username'=>'foo2','password'=>'fooPass',
                'disabled'=>null ,'accountExpirationDate'=>null ,'lastPasswordChangeDate'=>null ,'lockExpirationDate'=>null,
                'authorities'=>array('ROLE_OPERATOR','ROLE_USER')),
            $user
        );
    }

    public function testCreateAndDelete()
    {
        $repository = $this->getRepository();
        $user = array(
            'username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN','ROLE_USER'));
        $user = $repository->save($user);
        $this->assertEquals(1,$user['id']);
        $id = $user['id'];

        $user = array(
            'username'=>'foo2','password'=>'fooPass','authorities'=>array('ROLE_USER','ROLE_OPERATOR'));

        $user = $repository->save($user);
        $this->assertEquals(2,$user['id']);

        $repository->deleteById($id);

        $this->assertNull($repository->findOne(array('username'=>'foo')));

        $user = $repository->findOne(array('username'=>'foo2'));
        $this->assertEquals(
            array('id'=>2,'username'=>'foo2','password'=>'fooPass',
                'disabled'=>null ,'accountExpirationDate'=>null ,'lastPasswordChangeDate'=>null ,'lockExpirationDate'=>null,
                'authorities'=>array('ROLE_OPERATOR','ROLE_USER')),
            $user
        );

        $count = 0;
        $rows = $repository->getTableOperations()->executeQuery('SELECT * FROM rindow_authorities');
        foreach ($rows as $value) {
            $count++;
        }
        $this->assertEquals(2,$count);

        $repository->deleteById($user['id']);

        $count = 0;
        $rows = $repository->getTableOperations()->executeQuery('SELECT * FROM rindow_authorities');
        foreach ($rows as $value) {
            $count++;
        }
        $this->assertEquals(0,$count);
    }

    public function testCreateAndUpdate()
    {
        $repository = $this->getRepository();
        $user = array(
            'username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN','ROLE_USER'));
        $user = $repository->save($user);
        $this->assertEquals(1,$user['id']);
        $id = $user['id'];

        $user = array(
            'username'=>'foo2','password'=>'fooPass','authorities'=>array('ROLE_USER','ROLE_OPERATOR'));

        $user = $repository->save($user);
        $this->assertEquals(2,$user['id']);

        $user = array(
            'id'=>1,'username'=>'foo','password'=>'newPass','authorities'=>array('ROLE_ADMIN','ROLE_GUEST'));
        $user = $repository->save($user);


        $user = $repository->findOne(array('username'=>'foo'));
        $this->assertEquals(
            array('id'=>1,'username'=>'foo','password'=>'newPass',
                'disabled'=>null ,'accountExpirationDate'=>null ,'lastPasswordChangeDate'=>null ,'lockExpirationDate'=>null,
                'authorities'=>array('ROLE_ADMIN','ROLE_GUEST')),
            $user
        );

        $user = $repository->findOne(array('username'=>'foo2'));
        $this->assertEquals(
            array('id'=>2,'username'=>'foo2','password'=>'fooPass',
                'disabled'=>null ,'accountExpirationDate'=>null ,'lastPasswordChangeDate'=>null ,'lockExpirationDate'=>null,
                'authorities'=>array('ROLE_OPERATOR','ROLE_USER')),
            $user
        );
    }

    /**
     * @expectedException        Interop\Lenient\Dao\Exception\DuplicateKeyException
     * @expectedExceptionCode    -5
     */
    public function testDuplicateName()
    {
        $repository = $this->getRepository();
        $user = array(
            'username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_ADMIN','ROLE_USER'));
        $user = $repository->save($user);
        $this->assertEquals(1,$user['id']);

        $user = array(
            'username'=>'foo','password'=>'fooPass','authorities'=>array('ROLE_USER','ROLE_OPERATOR'));

        $user = $repository->save($user);
    }
}
