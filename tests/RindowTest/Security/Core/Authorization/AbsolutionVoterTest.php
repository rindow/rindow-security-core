<?php
namespace RindowTest\Security\Core\Authorization\AbsolutionVoterTest;

use PHPUnit\Framework\TestCase;
use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authorization\Vote\AbsolutionVoter;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;

class Test extends TestCase
{
	public function testVote()
	{
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));
		$voter = new AbsolutionVoter();
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AbsolutionVoter::PERMIT_ALL_ATTRIBUTE)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array(AbsolutionVoter::DENY_ALL_ATTRIBUTE)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_ABSTAIN,
			$voter->vote($authentication, $object=null, array()));
		$this->assertEquals(AccessDecisionVoter::ACCESS_ABSTAIN,
			$voter->vote($authentication, $object=null, array('OTHER_AUTHORITY')));
	}

	public function testSupports()
	{
		$voter = new AbsolutionVoter();
		$this->assertTrue($voter->supports(AbsolutionVoter::PERMIT_ALL_ATTRIBUTE));
		$this->assertTrue($voter->supports(AbsolutionVoter::DENY_ALL_ATTRIBUTE));
		$this->assertFalse($voter->supports('OTHER_AUTHORITY'));
		$this->assertFalse($voter->supports(null));
		$this->assertFalse($voter->supports(''));
	}
}
