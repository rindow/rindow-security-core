<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;

class AbsolutionVoter implements AccessDecisionVoter
{
    const PERMIT_ALL_ATTRIBUTE = 'PERMIT_ALL_ATTRIBUTE';
    const DENY_ALL_ATTRIBUTE   = 'DENY_ALL_ATTRIBUTE';

    public function supports(/*ConfigAttribute*/ $attribute)
    {
        if(self::PERMIT_ALL_ATTRIBUTE==$attribute ||
            self::DENY_ALL_ATTRIBUTE==$attribute )
            return true;
        return false;
    }

    public function vote(/*Authentication*/ $authentication, $object, array $attributes)
    {
        foreach ($attributes as  $attribute) {
            if(self::PERMIT_ALL_ATTRIBUTE==$attribute) {
                return AccessDecisionVoter::ACCESS_GRANTED;
            }

            if(self::DENY_ALL_ATTRIBUTE==$attribute) {
                return AccessDecisionVoter::ACCESS_DENIED;
            }
        }

        return AccessDecisionVoter::ACCESS_ABSTAIN;
    }
}
