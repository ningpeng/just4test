#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "pnunittest.h"

#include "pnstring.c"
void test_url(char* url)
{
	//hls url format http://RTSPA_IP:PORT/segmentID/start_second/[end_second] & SessionID= XXX
	//char url[1024] = "/2560001/0/10?SessionID=00026";
	
	printf("----test---- %s\n", url);
	char *purl = url + 1;
	
	char* psegment = strsep( &purl, "/" );
	printf("ret %s %s\n", psegment, purl );

	char* start_ts = strsep( &purl, "/" );
	printf("ret %s %s\n", start_ts, purl );
	
	char* end_ts = strsep( &purl, "&?" );
	printf("ret %s %s\n", end_ts, purl );
	
	printf("%s %s %s\n",psegment, start_ts ,end_ts);
	
}	
	
int main()
{
	char url[] = "/2560001/0/10?SessionID=00026";
	char url2[] = "/2560001/230?SessionID=00026";
	
	test_url(url);
	test_url(url2);
	
	
	
	
	char dest[32];
	
	strlcpy(dest, "123456", 32);
	PN_VERIFY_STR_EQUAL( dest, "12345" );

	strlcpy(dest, "11223344556677889900" , 5 );
	PN_VERIFY_STR_EQUAL(  dest, "1122" );
	
	strlcat(dest, "asdf", 5);
	PN_VERIFY_STR_EQUAL( dest, "1122");

	strlcat(dest, "asdf", 8 );
	PN_VERIFY_STR_EQUAL( dest, "1122asd" );

	strlcat(dest, "abcdefg", 32 );
	PN_VERIFY_STR_EQUAL( dest, "1122asdabcdefg" );
	return 0;
	
}
