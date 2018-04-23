#include <stdio.h>
#include "minunit.h"

#include "../stringex.h"

//------------------------------------------------------------------------------

MU_TEST(test1_strlcpy) 
{

        char buf[64];
        _strlcpy(buf, "12345", 4);
        mu_assert_string_eq("123", buf);
        _strlcpy(buf, "12345", 5);
        mu_assert_string_eq("1234", buf);
        _strlcpy(buf, "12345", 6);        
        mu_assert_string_eq("12345", buf);        
        _strlcpy(buf, "12345", 7);        
        mu_assert_string_eq("12345", buf); 
}

MU_TEST_SUITE(strlcpy_suite) 
{
        MU_RUN_TEST(test1_strlcpy);

}

MU_TEST(test1_strlcat) 
{

        char buf[128] = "012345";
        _strlcat(buf, "abc", 5);
        mu_assert_string_eq("012345", buf);

        _strlcat(buf, "abc", 10);
        mu_assert_string_eq("012345abc", buf);
        
        _strlcat(buf, "12345", 10);        
        mu_assert_string_eq("012345abc", buf);        
}

MU_TEST(test2_strlcat) 
{

        char buf[128] = "123456";
        _strlcat(buf, "abc", 5);
        mu_assert_string_eq("123456", buf);
        
        _strlcat(buf, "abc", 9);
        mu_assert_string_eq("123456ab", buf);
        
        _strlcat(buf, "12345", 10);        
        mu_assert_string_eq("123456ab1", buf);        
}

MU_TEST_SUITE(strlcat_suite) 
{
        MU_RUN_TEST(test1_strlcat);
        MU_RUN_TEST(test2_strlcat);

}
//------------------------------------------------------------------------------
MU_TEST(test1_strnsep)
{

        #define SOURCE "hello, world! welcome to china!"
        char delim[] = " ,!";
        char *token;
        char buf[64];
        char *s = buf;

        strcpy(s, SOURCE);
        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "hello");
        mu_assert_string_eq(s, " world! welcome to china!");    

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "");
        mu_assert_string_eq(s, "world! welcome to china!");            

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "world");
        mu_assert_string_eq(s, " welcome to china!"); 
                
        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "");
        mu_assert_string_eq(s, "welcome to china!");   

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "welcome");
        mu_assert_string_eq(s, "to china!");  

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "to");
        mu_assert_string_eq(s, "china!");          

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "china");
        mu_assert_string_eq(s, "");  

        token = _strnsep(&s, delim, strlen(s));
        mu_assert_string_eq(token, "");
        mu_assert(s == NULL , "s should be NULL");  
}

MU_TEST(test2_strnsep)
{
        //char *source = "parm1=value1&parm2=value2&param3=value3"; // it maybe core
        char source[] = "parm1=value1&parm2=value2&param3=value3"; 
        char delim[] = "&";
        char *s = source;

        char *token = _strnsep(&s, delim, strlen(s));

        mu_assert_string_eq(token, "parm1=value1");
        mu_assert_string_eq(s, "parm2=value2&param3=value3");

        //printf("source %s\n", source); //_strnsep will change source string



}

MU_TEST_SUITE(strnsep_suite) 
{
        MU_RUN_TEST(test1_strnsep);
        MU_RUN_TEST(test2_strnsep);

}
//------------------------------------------------------------------------------
MU_TEST(test1_strcspn)
{
        char source[] = "parm1=value1&parm2=value2&param3=value3"; 
        
        int r = strcspn( source, "&=" );
        mu_assert_int_eq(r, 5);
        
        r = strcspn( source, "xyz" );
        mu_assert_int_eq(r, strlen(source));//can found "xyz"

        r = strcspn( source, "p" );
        mu_assert_int_eq(r, 0);     

}

MU_TEST(test2_str_ncspn)
{
        char source[] = "parm1=value1&parm2=value2&param3=value3"; 
        
        int r = _strn_cspn( source, "&=" , sizeof(source));
        mu_assert_int_eq(r, 5);
        
        r = _strn_cspn( source, "xyz", sizeof(source) );
        mu_assert_int_eq(r, strlen(source));//can found "xyz"

        r = _strn_cspn( source, "p" , sizeof(source) );
        mu_assert_int_eq(r, 0);

        r = _strn_cspn( source, "&=" , 4 );
        mu_assert_int_eq(r, 4);

        r = _strn_cspn( source, "&=" , 5 );
        mu_assert_int_eq(r, 5);

        r = _strn_cspn( source, "&=" , 6 );
        mu_assert_int_eq(r, 5);

        r = _strn_cspn( source, "&" , 10 );
        mu_assert_int_eq(r, 10);

        r = _strn_cspn( source, "&" , 11 );
        mu_assert_int_eq(r, 11);

        r = _strn_cspn( source, "&" , 12 );
        mu_assert_int_eq(r, 12);

        r = _strn_cspn( source, "&" , 13 );
        mu_assert_int_eq(r, 12);

        r = _strn_cspn( source, "&" , 14 );
        mu_assert_int_eq(r, 12);

        r = _strn_cspn( source, "&" , 15 );
        mu_assert_int_eq(r, 12);
}

MU_TEST_SUITE(str_ncspn_suite) 
{
        MU_RUN_TEST(test1_strcspn);
        MU_RUN_TEST(test2_str_ncspn);
}

//------------------------------------------------------------------------------
MU_TEST_SUITE(test1_pnx_str_suite);




int main()
{

        MU_RUN_SUITE(strlcpy_suite);
        
        MU_RUN_SUITE(strlcat_suite);

        MU_RUN_SUITE(strnsep_suite);

        MU_RUN_SUITE(str_ncspn_suite);

        MU_RUN_SUITE(test1_pnx_str_suite);

        MU_REPORT();        
        
        return 0;
}