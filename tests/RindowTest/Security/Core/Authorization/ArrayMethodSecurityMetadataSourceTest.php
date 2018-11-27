<?php
namespace RindowTest\Security\Core\Authorization\ArrayMethodSecurityMetadataSourceTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Method\ArrayMethodSecurityMetadataSource;
use Rindow\Aop\ProceedingJoinPointInterface;

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
    public function test()
    {
    	$config = array(
            'Foo\\Test::someaction' => array('ROLE_USER'),
    	);
    	$metadata = new ArrayMethodSecurityMetadataSource();
    	$metadata->setConfig($config);

    	$invocation = new TestInvocation('Foo\\Test::someaction');
    	$this->assertTrue($metadata->supports($invocation));
    	$this->assertEquals(array('ROLE_USER'),$metadata->getAttributes($invocation));

    	$invocation = new TestInvocation('Foo\\Test::public');
    	$this->assertTrue($metadata->supports($invocation));
    	$this->assertNull($metadata->getAttributes($invocation));

    	$dummy = new \stdClass();
    	$this->assertFalse($metadata->supports($dummy));
    	$this->assertFalse($metadata->supports(array()));
    }
}
