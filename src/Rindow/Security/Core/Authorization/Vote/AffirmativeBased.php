<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authorization\Exception;

class AffirmativeBased extends AbstractAccessDecisionManager
{
    /*
     * Copy from the AbstractAccessDecisionManager
     */
    public static function factory($serviceLocator,$componentName,array $args)
    {
        $decisionVoters = array();
        if(isset($args['voters'])) {
            foreach ($args['voters'] as $voterName) {
                $decisionVoters[] = $serviceLocator->get($voterName);
            }
        }
        return new self($decisionVoters);
    }

    /**
     * @param Array<AccessDecisionVoter> $decisionVoters
     */
    public function __construct(array $decisionVoters=null)
    {
        parent::__construct($decisionVoters);
    }

    public function decide(/*Authentication*/ $authentication, /*Object*/ $object, array $attributes)
    {
        $deny = 0;
        foreach($this->getDecisionVoters() as $voter) {
            $result = $voter->vote($authentication, $object, $attributes);
            switch($result) {
                case AccessDecisionVoter::ACCESS_GRANTED:
                    return true;

                case AccessDecisionVoter::ACCESS_DENIED:
                    ++$deny;
                    break;

                default:
                    break;
            }
        }

        if($deny > 0) {
            throw new Exception\AccessDeniedException('Access is denied.');
        }

        $this->checkAllowIfAllAbstainDecisions();
    }
}
