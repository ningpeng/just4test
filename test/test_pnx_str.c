
#include <stdio.h>
#include "minunit.h"

#include "../stringex.h"
#include "../pnx_str.h"

#if 0
int test2_pnx_strsep()
{
	char source[] = "parm1=value1&parm2=value2&param3=value3";
	char delim[] = "&";

	pnx_str_t  src ;
	pnx_str_attach(&src, source);
	pnx_str_print(&src);

	pnx_str_t  s = src;
	pnx_str_t token;

	for(token = pnx_strsep(&s, delim); 0==pnx_str_isnull(&token); token=pnx_strsep(&s, delim) ) {
		printf("token:");
		pnx_str_print(&token);
		printf("value:");
		pnx_str_print(&s);

		pnx_str_t name;
		pnx_str_t value = token;

		name=pnx_strsep(&value, "=");

		printf("name %.*s value %.*s\n", name.len, name.data, value.len, value.data); 
		
		printf("-------------------------\n");
		
	}

	return 0;
}

#endif

MU_TEST(test1_pnx_str_t) 
{

        char buf[64];
        pnx_str_t  str = pnx_string("aaaaa");
        mu_assert_int_eq(5, str.len);
        mu_assert_int_eq( 0 , pnx_strcmp(&str, "aaaaa"));



}


MU_TEST(test2_pnx_strnsep) 
{
	pnx_str_t  src = pnx_string( "parm1=value1&parm2=value2&param3=value3" );
	char delim[] = "&";
	pnx_str_t  s = src;
	//pnx_str_t token = pnx_strsep_wrong(&s, delim); 

	pnx_str_print(&src);

}

MU_TEST(test3_pnx_str_split)
{
	pnx_str_t  src = pnx_string( "parm1=value1&parm2=value2&param3=value3" );
	char delim[] = "&";

	pnx_str_t  token , value;

	token = pnx_str_split(&src, delim, &value);
	mu_assert_int_eq( 0 , pnx_strcmp(&token, "parm1=value1"));
	mu_assert_int_eq( 0 , pnx_strcmp(&value, "parm2=value2&param3=value3"));

	token = pnx_str_split(&value, delim, &value);
	mu_assert_int_eq( 0 , pnx_strcmp(&token, "parm2=value2"));
	mu_assert_int_eq( 0 , pnx_strcmp(&value, "param3=value3"));	

	pnx_str_t  name , namevalue;
	name = pnx_str_split(&token, "&=", &namevalue);
	mu_assert_int_eq( 0 , pnx_strcmp(&name, "parm2"));
	mu_assert_int_eq( 0 , pnx_strcmp(&namevalue, "value2"));	

	name = pnx_str_split(&value, "&=", &namevalue);
	mu_assert_int_eq( 0 , pnx_strcmp(&name, "param3"));
	mu_assert_int_eq( 0 , pnx_strcmp(&namevalue, "value3"));	

	//找不到返回 null_string
	name = pnx_str_split(&token, "#!s",  &namevalue);
	mu_assert_int_eq( 0 , pnx_strcmp(&name, "parm2=value2"));
	mu_check( namevalue.data == NULL );

	//空参数找不到返回 null_string
	name = pnx_str_split( NULL, "###", &namevalue);
	mu_check( name.data == NULL );
	mu_check( namevalue.data == NULL );
		
	//空参数找不到返回 null_string
	token.data = NULL;
	name = pnx_str_split( &token, "###", &namevalue);
	mu_check( name.data == NULL );
	mu_check( namevalue.data == NULL );




}

MU_TEST_SUITE(test1_pnx_str_suite) 
{
        MU_RUN_TEST(test1_pnx_str_t);
        //MU_RUN_TEST(test2_pnx_strnsep);
        MU_RUN_TEST(test3_pnx_str_split);
}