<?php
namespace Rindow\Security\Core\Authorization\Vote;

use Interop\Lenient\Security\Authorization\AccessDecisionManager;
use Rindow\Security\Core\Authorization\Exception;

abstract class AbstractAccessDecisionManager implements AccessDecisionManager
{
    protected $allowIfAllAbstainDecisions = false;
    protected $decisionVoters = array();

    /*
     * Copy to extends class
     *
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
     */

    /**
     * @param Array<AccessDecisionVoter> $decisionVoters
     */
    protected function __construct(array $decisionVoters=null)
    {
        if($decisionVoters)
            $this->setDecisionVoters($decisionVoters);
    }

    /**
     * @param Array<AccessDecisionVoter> $decisionVoters
     */
    public function setDecisionVoters(array $decisionVoters)
    {
        $this->decisionVoters = $decisionVoters;
    }

    /**
     * @param MessageSource $messageSource
     */
    public function setMessageSource(/*MessageSource*/ $messageSource)
    {
        # code...
    }

    /**
     * @return void
     * @throws AccessDeniedException
     */
    protected function checkAllowIfAllAbstainDecisions()
    {
        if(!$this->isAllowIfAllAbstainDecisions()) {
            throw new Exception\AccessDeniedException('Access is denied.');
        }
    }

    /**
     * @return Array<AccessDecisionVoter<? extends Object>>
     */
    public function getDecisionVoters()
    {
        return $this->decisionVoters;
    }

    public function isAllowIfAllAbstainDecisions()
    {
        return $this->allowIfAllAbstainDecisions;
    }

    /**
     *  @param boolean $allowIfAllAbstainDecisions
     */
    public function setAllowIfAllAbstainDecisions(/*boolean*/ $allowIfAllAbstainDecisions) 
    {
        $this->allowIfAllAbstainDecisions = $allowIfAllAbstainDecisions;
    }

    public function supports(/*ConfigAttribute*/ $attribute)
    {
        foreach($this->decisionVoters as $voter) {
            if(!$voter->supports($attribute))
                return false;
        }
        return true;
    }
}