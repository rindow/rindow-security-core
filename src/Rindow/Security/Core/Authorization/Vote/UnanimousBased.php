<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authorization\Exception;

class UnanimousBased extends AbstractAccessDecisionManager
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

    public function __construct(array $decisionVoters=null)
    {
        parent::__construct($decisionVoters);
    }

    public function decide(/*Authentication*/ $authentication, /*Object*/ $object, array $attributes)
    {
        $grant = 0;
        foreach ($attributes as $attribute) {
            foreach ($this->getDecisionVoters() as $voter) {
                $result = $voter->vote($authentication, $object, array($attribute));

                switch ($result) {
                    case AccessDecisionVoter::ACCESS_GRANTED:
                        ++$grant;
                        break;

                    case AccessDecisionVoter::ACCESS_DENIED:
                        throw new Exception\AccessDeniedException('Access is denied.');

                    default:
                        break;
                }
            }
        }

        if ($grant > 0) {
            return;
        }

        $this->checkAllowIfAllAbstainDecisions();
    }
}
