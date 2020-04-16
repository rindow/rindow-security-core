<?php
namespace Rindow\Security\Core;

class Module
{
    public function getConfig()
    {
        return array(
            'annotation' => array(
                'aliases' => array(
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\AccessControlled' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\AccessControlled',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\Authenticated' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\Authenticated',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\DeclaresRoles' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\DeclaresRoles',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\DenyAll' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\DenyAll',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\FullyAuthenticated' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\FullyAuthenticated',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\PermitAll' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\PermitAll',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\RolesAllowed' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\RolesAllowed',
                    'Interop\\Lenient\\Security\\Authorization\\Annotation\\RunAs' =>
                        'Rindow\\Security\\Core\\Authorization\\Annotation\\RunAs',
                ),
            ),
            'aop' => array(
                'plugins' => array(
                    'Rindow\\Security\\Core\\Authorization\\Method\\AnnotatedComponentRegistrar'=>true,
                ),
                'authorization' => array(
                    'advisorName' => 'Rindow\\Security\\Core\\Authorization\\DefaultAnnotatedMethodSecurityAdvisor',
                    'adviceName'  => 'beforeAccess',
                    'adviceDefinition' => array(
                        'type' => 'before',
                        'component' => 'Rindow\\Security\\Core\\Authorization\\DefaultMethodSecurityAdvisor',
                    ),
                ),
                'aspects' => array(
                    'Rindow\\Security\\Core\\Authorization\\DefaultArrayConfiguredMethodSecurityAdvisor' => array(
                        'component' => 'Rindow\\Security\\Core\\Authorization\\DefaultMethodSecurityAdvisor',
                        'advices' => array(
                            'beforeAccess' => array(
                                'type' => 'before',
                                // 'pointcut_ref' => array(
                                //      'your_pointcut_signature1' => true,
                                //      'your_pointcut_signature2' => true,
                                // ),
                            ),
                        ),
                    ),
                ),
            ),
            'database' => [
                'repository' => [
                    'GenericSqlRepository' => [
                        'extends' => [
                            'Rindow\\Security\\Core\\Authentication\\UserDetails\\UserManager\\UserDetailsSqlRepository' => true,
                        ]
                    ],
                ],
            ],
            'container' => array(
                'aliases' => array(
                    //'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage' => 'Your_Security_Context_Strage',
                    //'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService' => 'Your_UserDetailsManager',
                    //'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManagerDataSource' => 'Sql_data_source',
                    //'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManagerTransactionBoundary' => 'Sql_Transaction_Boundary',
                    //'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsRepository' => 'Your_UserDetails_Repository'
                    // OLD SERVICE
                    ////'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsRepositoryFactory' => 'Your_UserDetailsRepositoryFactory',
                    ////'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsDataStore' => 'Your_UserDetailsDataStore',
                ),
                'components' => array(
                    //
                    // Authentication Compoments
                    //
                    'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Support\\SecurityContext',
                        'properties' => array(
                            'strage' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage'),
                            'key' => array('value'=>'Rindow.Security.Authentication.DefaultSecurityContext'),
                            'lifeTime' => array('config'=>'security::authentication::default::securityContext::lifetime'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Support\\AuthenticationTrustResolver',
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultProviderManager' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Support\\ProviderManager',
                        'factory' => 'Rindow\\Security\\Core\\Authentication\\Support\\ProviderManagerFactory::factory',
                        'factory_args' => array('config'=>'security::authentication::default'),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Provider\\AnonymousAuthenticationProvider',
                        'constructor_args' => array(
                            'key' => array('config'=>'security::secret'),
                            'defaultPrincipal' => array('config'=>'security::authentication::default::anonymous::principal'),
                            'defaultAuthorities' => array('config'=>'security::authentication::default::anonymous::authorities'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Provider\\RememberMeAuthenticationProvider',
                        'constructor_args' => array(
                            'key' => array('config'=>'security::secret'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\Provider\\DaoAuthenticationProvider',
                        'constructor_args' => array(
                            'userDetailsService' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsService'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultInMemoryUserDetailsManager' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\UserDetails\\UserManager\\InMemoryUserDetailsManager',
                        'properties' => array(
                            'config' => array('config'=>'security::authentication::default::users'),
                        ),
                    ),
                    //
                    //  UserDetailsManager of Traditional SQL Style
                    //
                    'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManager' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\UserDetails\\UserManager\\SqlUserDetailsManager',
                        'constructor_args' => array(
                            'dataSource' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManagerDataSource'),
                            'transactionBoundary' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSqlUserDetailsManagerTransactionBoundary'),
                            'repositoryName' => array('config'=>'security::authentication::default::repositoryName'),
                            'authoritiesRepositoryName' => array('config'=>'security::authentication::default::authoritiesRepositoryName'),
                        ),
                    ),
                    //
                    //  UserDetailsManager of Repository Style
                    //
                    'Rindow\\Security\\Core\\Authentication\\DefaultCrudRepositoryUserDetailsManager' => array(
                        'class' => 'Rindow\\Security\\Core\\Authentication\\UserDetails\\UserManager\\CrudRepositoryUserDetailsManager',
                        'properties' => array(
                            'repository' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsRepository'),
                            'maxPasswordAge' => array('config' => 'security::authentication::default::maxPasswordAge'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authentication\\DefaultUserDetailsSqlRepository'=>array(
                        'parent' => 'Rindow\\Database\\Dao\\Repository\\AbstractSqlRepository',
                        'class' => 'Rindow\\Security\\Core\\Authentication\\UserDetails\\UserManager\\UserDetailsSqlRepository',
                        'properties' => array(
                            'tableName' => array('config'=>'security::authentication::default::repositoryName'),
                            'authoritiesTableName' => array('config'=>'security::authentication::default::authoritiesRepositoryName'),
                        ),
                    ),
                    //
                    // Authorization Compoments
                    //
                    'Rindow\\Security\\Core\\Authorization\\DefaultAbsolutionVoter' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Vote\\AbsolutionVoter',
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultRoleVoter' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Vote\\RoleVoter',
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultAuthenticatedVoter' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Vote\\AuthenticatedVoter',
                        'properties' => array(
                            'authenticationTrustResolver' => array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultMethodAccessDecisionManager' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Vote\\UnanimousBased',
                        'factory' => 'Rindow\\Security\\Core\\Authorization\\Vote\\UnanimousBased::factory',
                        'factory_args' => array(
                            'voters' => array(
                                'Rindow\\Security\\Core\\Authorization\\DefaultAbsolutionVoter',
                                'Rindow\\Security\\Core\\Authorization\\DefaultRoleVoter',
                                'Rindow\\Security\\Core\\Authorization\\DefaultAuthenticatedVoter',
                            ),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultAnnotationMethodSecurityMetadataSource' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Method\\AnnotationMethodSecurityMetadataSource',
                        'properties' => array(
                            'annotationReader' => array('ref'=>'AnnotationReader'),
                            'roleVoter' => array('ref'=>'Rindow\\Security\\Core\\Authorization\\DefaultRoleVoter'),
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultArrayMethodSecurityMetadataSource' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Method\\ArrayMethodSecurityMetadataSource',
                        'properties' => array(
                            'config' => array('config'=>'security::authorization::method::metadata'),
                        ),
                    ),

                    'Rindow\\Security\\Core\\Authorization\\DefaultDelegatingMethodSecurityMetadataSource' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Method\\DelegatingMethodSecurityMetadataSource',
                        'factory' => 'Rindow\\Security\\Core\\Authorization\\Method\\DelegatingMethodSecurityMetadataSource::factory',
                        'factory_args' => array(
                            'sources' => array(
                                'Rindow\\Security\\Core\\Authorization\\DefaultAnnotationMethodSecurityMetadataSource',
                                'Rindow\\Security\\Core\\Authorization\\DefaultArrayMethodSecurityMetadataSource',
                            ),
                            'configCacheFactory' => 'ConfigCacheFactory',
                            // If you want debug informations, it inject following;
                            // 'debug' => true,
                            // 'logger' => 'Logger',
                        ),
                    ),
                    'Rindow\\Security\\Core\\Authorization\\DefaultMethodSecurityAdvisor' => array(
                        'class' => 'Rindow\\Security\\Core\\Authorization\\Method\\MethodSecurityAdvisor',
                        'properties' => array(
                            //'authenticationManager' =>  array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultContextStrage'),
                            'authenticationManager' =>  array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultProviderManager'),
                            'securityContext' =>        array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultSecurityContext'),
                            'securityMetadataSource' => array('ref'=>'Rindow\\Security\\Core\\Authorization\\DefaultDelegatingMethodSecurityMetadataSource'),
                            'accessDecisionManager' =>  array('ref'=>'Rindow\\Security\\Core\\Authorization\\DefaultMethodAccessDecisionManager'),
                            'authenticationTrustResolver' =>  array('ref'=>'Rindow\\Security\\Core\\Authentication\\DefaultAuthenticationTrustResolver'),
                        ),
                    ),
                ),
            ),
            // security configuration
            //
            //'security' => array(
            //    'secret' => 'secret string for your server',
            //    'authentication' => array(
            //        'default' => array(
            //            'anonymous' => array(
            //                'principal' => 'anonymous',
            //                'authorities' => array('ANONYMOUS'=>true),
            //            ),
            //            'repositoryName' => 'rindow_authusers',
            //            'providers' => array(
            //                'Rindow\\Security\\Core\\Authentication\\DefaultAnonymousAuthenticationProvider' => true,
            //                'Rindow\\Security\\Core\\Authentication\\DefaultRememberMeAuthenticationProvider' => true,
            //                'Rindow\\Security\\Core\\Authentication\\DefaultDaoAuthenticationProvider' => true,
            //            ),
            //            'securityContext' => array(
            //                'lifetime' => 'Number of seconds of lifetime.',
            //            ),
            //        ),
            //    ),
            //),
        );
    }

    public function checkDependency($config)
    {
        /*
        if(isset($config['module_manager']['aop_manager'])&&
            $config['module_manager']['aop_manager']    ) {
            if(!isset($config['aop']['aspects']['Rindow\\Database\\Dao\\DefaultDaoExceptionAdvisor']
                ['advices']['afterThrowingAdvice']['type'])) {
                throw new \DomainException('When it use AOP, it need to include the DefaultDaoExceptionAdvisor. It recomends to include the Rindow Dao Module.');
            }
            if(!isset($config['aop']['aspects']['Rindow\\Transaction\\DefaultTransactionAdvisor']
                ['advices']['required']['type'])) {
                throw new \DomainException('When it use AOP, it need to include the DefaultTransactionAdvisor. It recomends to include the Rindow (Local or Distribured) Transaction Module.');
            }
        }
        */
    }
}
