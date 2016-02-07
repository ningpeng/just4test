#ifndef _PN_C_UNITTEST_
#define _PN_C_UNITTEST_

#include <stdio.h>
#include <stdlib.h>

#define ERRLOG(x) printf x
#define DEBUGLOG(x) printf x

#define TRACE printf

#define ASSERT_FAIL_ACTION	(abort());

#define PN_VERIFY( condition  ) \
do{ \
    if( !(condition) ){ \
               ERRLOG(("Err: file:%s line:%d VERIFY( %s )FAIL!" , __FILE__ ,__LINE__ , (#condition) ));\
      ASSERT_FAIL_ACTION;\
    }\
}while(0)\


#define PN_VERIFY_STR_EQUAL( str1 , str2  ) \
do{ \
    if(0!=strcmp(str1, str2) ){ \
               ERRLOG(("ERR: file:%s line:%d VERIFY_STRING( %s==%s )FAIL! " , __FILE__ ,__LINE__ , (#str1), (#str2) ));\
      ASSERT_FAIL_ACTION;\
    }\
}while(0)\






#endif
