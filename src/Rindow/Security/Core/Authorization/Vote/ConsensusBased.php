<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authorization\Exception;

class ConsensusBased extends AbstractAccessDecisionManager
{
    protected $allowIfEqualGrantedDeniedDecisions = true;

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

    public function isAllowIfEqualGrantedDeniedDecisions()
    {
        return $this->allowIfEqualGrantedDeniedDecisions;
    }

    public function setAllowIfEqualGrantedDeniedDecisions($allowIfEqualGrantedDeniedDecisions)
    {
        $this->allowIfEqualGrantedDeniedDecisions = $allowIfEqualGrantedDeniedDecisions;
    }

    public function decide(/*Authentication*/ $authentication, /*Object*/ $object, array $attributes)
    {
        $grant = 0;
        $deny = 0;
        foreach ($this->getDecisionVoters() as $voter) {
            $result = $voter->vote($authentication, $object, $attributes);
            switch ($result) {
                case AccessDecisionVoter::ACCESS_GRANTED:
                    ++$grant;
                    break;

                case AccessDecisionVoter::ACCESS_DENIED:
                    ++$deny;
                    break;
            }
        }

        if($grant > $deny)
            return;
        if($grant < $deny)
            throw new Exception\AccessDeniedException('Access is denied.');

        if($grant > 0) {
            if($this->allowIfEqualGrantedDeniedDecisions)
                return;
            throw new Exception\AccessDeniedException('Access is denied.');
        }

        $this->checkAllowIfAllAbstainDecisions();
    }
}
