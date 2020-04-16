<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Rindow\Database\Dao\Repository\GenericSqlRepository;
use Rindow\Database\Dao\Exception;

class UserDetailsSqlRepository extends GenericSqlRepository
{
    protected $tableName = 'rindow_authusers';
    protected $authoritiesTableName = 'rindow_authorities';

    public function setTableName($tableName)
    {
        if($tableName==null)
            return;
        parent::setTableName($tableName);
    }

    public function setAuthoritiesTableName($authoritiesTableName)
    {
        if($authoritiesTableName==null)
            return;
        $this->authoritiesTableName = $authoritiesTableName;
    }

    protected function cascadedFieldConfig()
    {
        $config = parent::cascadedFieldConfig();
        array_push($config,array(
              'property'=>'authorities',
              'tableName'=>$this->authoritiesTableName,
              'masterIdName'=>'userid',
              'fieldName'=>'authority',
        ));
        return $config;
    }
}
