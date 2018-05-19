
#include <stdio.h>
#include "minunit.h"

#include "../runtime_config.h"



#define CDM_HTTP_PORT  8090
#define CDM_RUDP_PORT  8091
#define TEST_RATE      100.2
#define TEST_RATE_INT  100.65


#define MYSQL_SERVER      "sz.asdf5.xyz"
#define MYSQL_USER        "root"
#define MYSQL_PASS        "xxxx.123" 
#define MYSQL_DB          "dbname"


MU_TEST(test1_initcfg) 
{
    double  ret = 0;
    char str[64];
    initialize_config_file("config.tmp");

    //假如已经有配置项,  缺省配置项将不会更新
    SET_DEFAULT_INT_CONFIG(CDM_HTTP_PORT);
    SET_DEFAULT_INT_CONFIG(CDM_RUDP_PORT);
    SET_DEFAULT_NUM_CONFIG(TEST_RATE);
    SET_DEFAULT_INT_CONFIG(TEST_RATE_INT);

    SET_DEFAULT_STR_CONFIG(MYSQL_SERVER);
    SET_DEFAULT_STR_CONFIG(MYSQL_USER);
    SET_DEFAULT_STR_CONFIG(MYSQL_PASS);
    SET_DEFAULT_STR_CONFIG(MYSQL_DB);

    ret = CONFIG_VALUE(CDM_HTTP_PORT);
    mu_assert_int_eq(CDM_HTTP_PORT,ret);

    ret = CONFIG_VALUE(CDM_RUDP_PORT);
    mu_assert_int_eq(CDM_RUDP_PORT,ret);

    ret = get_config_num("TEST_RATE");
    mu_assert_double_eq(TEST_RATE, ret);

    ret = get_config_num("TEST_RATE_INT");
    mu_assert_int_eq(100, ret);

    ret = get_configuration_string("MYSQL_SERVER", str, sizeof(str));
    mu_assert_string_eq(MYSQL_SERVER, str);
    mu_assert_int_eq(1, ret);

    ret = get_configuration_string("MYSQL_USER", str, sizeof(str));
    mu_assert_string_eq(MYSQL_USER, str);
    mu_assert_int_eq(1, ret);

    ret = get_configuration_string("MYSQL_PASS", str, sizeof(str));
    mu_assert_string_eq(MYSQL_PASS, str);
    mu_assert_int_eq(1, ret);

    ret = get_configuration_string("MYSQL_DB", str, sizeof(str));
    mu_assert_string_eq(MYSQL_DB, str);
    mu_assert_int_eq(1, ret);

    //read cfg fail , no config item
    ret = get_configuration_string("MYSQL_DBxxx", str, sizeof(str));
    mu_assert_int_eq(0, ret);
}

MU_TEST_SUITE(runtimecfg_suite) 
{
        MU_RUN_TEST(test1_initcfg);
}

int main()
{

        MU_RUN_SUITE(runtimecfg_suite);


        MU_REPORT();        
        
        return 0;
}