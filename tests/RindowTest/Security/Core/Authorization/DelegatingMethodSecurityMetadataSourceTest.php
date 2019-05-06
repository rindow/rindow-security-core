<?php
namespace RindowTest\Security\Core\Authorization\DelegatingMethodSecurityMetadataSourceTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Method\AbstractMethodSecurityMetadataSource;
use Rindow\Security\Core\Authorization\Method\DelegatingMethodSecurityMetadataSource;
use Rindow\Aop\ProceedingJoinPointInterface;
use Rindow\Stdlib\Cache\ConfigCache\ConfigCacheFactory;

class TestLogger
{
    public $log = array();

    public function logging($text)
    {
        $this->log[] = $text;
    }
}

class TestMetadataSource extends AbstractMethodSecurityMetadataSource
{
    protected $config;
    protected $logger;

    public function __construct($config=null, $logger=null)
    {
        if($config)
            $this->setConfig($config);
        if($logger)
            $this->setLogger($logger);
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    public function setConfig($config)
    {
        $this->config = $config;
    }

    public function getAttributes($invocation)
    {
        $this->logger->logging('start getAttributes');
        if(!$this->supports($invocation))
            return null;

        $signatureString = $invocation->getSignatureString();
        if(!isset($this->config[$signatureString]))
            return null;
        $this->logger->logging('match '.$signatureString);
        return $this->config[$signatureString];
    }
}

class TestInvocation implements ProceedingJoinPointInterface
{
    protected $signatureString;

    public function __construct($signatureString)
    {
        $this->signatureString = $signatureString;
    }
    public function proceed(array $args=null){}
    public function getTarget(){}
    public function getParameters(){}
    public function getAction(){}
    public function getSignature(){}
    public function getSignatureString()
    {
        return $this->signatureString;
    }
    public function toString(){}
}


class Test extends TestCase
{
    public function setUp()
    {
    }

    public function getConfigCacheFactory()
    {
        $config = array(
                //'fileCachePath'   => __DIR__.'/../cache',
                'configCache' => array(
                    'enableMemCache'  => true,
                    'enableFileCache' => true,
                    'forceFileCache'  => false,
                ),
                //'apcTimeOut'      => 20,
                'memCache' => array(
                    'class' => 'Rindow\Stdlib\Cache\SimpleCache\ArrayCache',
                ),
                'fileCache' => array(
                    'class' => 'Rindow\Stdlib\Cache\SimpleCache\ArrayCache',
                ),
        );
        $configCacheFactory = new ConfigCacheFactory($config);
        return $configCacheFactory;
    }

    public function testCache()
    {
        $logger = new TestLogger();
        $configCacheFactory = $this->getConfigCacheFactory();
        $config1 = array(
            'Foo\\Test::someaction' => array('ROLE_USER'),
        );
        $metadata1 = new TestMetadataSource($config1,$logger);
        $config2 = array(
            'Foo\\Test::adminaction' => array('ROLE_ADMIN'),
        );
        $metadata2 = new TestMetadataSource($config2,$logger);
        $metadata = new DelegatingMethodSecurityMetadataSource(array($metadata1,$metadata2),$configCacheFactory);

        $invocation = new TestInvocation('Foo\\Test::someaction');
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));
        $this->assertCount(2,$logger->log);
        $this->assertEquals('start getAttributes',$logger->log[0]);
        $this->assertEquals('match Foo\\Test::someaction',$logger->log[1]);

        $invocation = new TestInvocation('Foo\\Test::public');
        $this->assertTrue($metadata->supports($invocation));
        $this->assertNull($metadata->getAttributes($invocation));
        $this->assertCount(4,$logger->log);
        $this->assertEquals('start getAttributes',$logger->log[2]);
        $this->assertEquals('start getAttributes',$logger->log[3]);

        $invocation = new TestInvocation('Foo\\Test::someaction');
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));
        $this->assertCount(4,$logger->log);

        $invocation = new TestInvocation('Foo\\Test::public');
        $this->assertTrue($metadata->supports($invocation));
        $this->assertNull($metadata->getAttributes($invocation));
        $this->assertCount(4,$logger->log);


        $metadata = new DelegatingMethodSecurityMetadataSource(array($metadata1,$metadata2),$configCacheFactory);
        $invocation = new TestInvocation('Foo\\Test::someaction');
        $this->assertTrue($metadata->supports($invocation));
        $this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));
        $this->assertCount(4,$logger->log);


        $dummy = new \stdClass();
        $this->assertFalse($metadata->supports($dummy));
        $this->assertFalse($metadata->supports(array()));
    }
}
