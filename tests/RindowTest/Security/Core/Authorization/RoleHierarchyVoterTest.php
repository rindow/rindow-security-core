<?php
namespace RindowTest\Security\Core\Authorization\RoleHierarchyVoterTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Vote\RoleHierarchyVoter;
use Rindow\Security\Core\Authorization\Support\RoleHierarchy;
use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;

class Test extends TestCase
{
	public function testVote()
	{
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_ADMIN'));
		$roleHierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'      => array('ROLE_USER'),
        ));
		$voter = new RoleHierarchyVoter($roleHierarchy);

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array('ROLE_USER')));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array('ROLE_OTHER')));
		$this->assertEquals(AccessDecisionVoter::ACCESS_ABSTAIN,
			$voter->vote($authentication, $object=null, array()));
		$this->assertEquals(AccessDecisionVoter::ACCESS_ABSTAIN,
			$voter->vote($authentication, $object=null, array('OTHER_AUTHORITY')));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array('ROLE_USER','ROLE_OTHER')));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array('ROLE_OTHER','ROLE_USER')));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array('OTHER_AUTHORITY','ROLE_USER')));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array('OTHER_AUTHORITY','ROLE_OTHER')));
	}

	public function testSupports()
	{
		$voter = new RoleHierarchyVoter();
		$this->assertTrue($voter->supports('ROLE_USER'));
		$this->assertFalse($voter->supports('OTHER_AUTHORITY'));
		$this->assertFalse($voter->supports(null));
		$this->assertFalse($voter->supports(''));
	}
}
