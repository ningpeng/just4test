#include <stdio.h>
#include <assert.h> 
#include <string.h>

#include "http_parser.h"

/*
static http_parser_settings settings_null =
  {.on_message_begin = 0
  ,.on_header_field = 0
  ,.on_header_value = 0
  ,.on_url = 0
  ,.on_status = 0
  ,.on_body = 0
  ,.on_headers_complete = 0
  ,.on_message_complete = 0
  };
 */
 
 #define MAX_HTTP_HEADERS (20)
 
  typedef struct {

    char *url;
    char *method;
    int header_lines;
    char *header_field[MAX_HTTP_HEADERS];
	char *header_value[MAX_HTTP_HEADERS];
    char *body;
    size_t body_length;

} http_request_t;
  
int
request_url_cb (http_parser *parser, const char *buf, size_t len)
{
	http_request_t *http_request = parser->data;
	assert(parser!=NULL);
	printf("request_url_cb %d %.*s\n" ,(int)len, (int)len, buf);
  
	http_request->url = strndup(buf, len);
	return 0;
}


int
message_begin_cb (struct http_parser *parser)
{
  assert(parser!=NULL);
  printf("message_begin_cb\n");
  
  http_request_t *http_request = parser->data;
  
  http_request->header_lines = 0;
  return 0;
}

int header_field_cb(http_parser *parser, const char *buf, size_t len)
{
	assert(parser!=NULL && buf!=NULL);
	printf("header_field_cb %d %.*s\n", (int)len, (int)len , buf);
	
	
	http_request_t *http_request = parser->data;
		
	http_request->header_field[http_request->header_lines] = strndup(buf, len);
	
	http_request->header_lines++;
	
	return 0;
}

int header_value_cb(http_parser *parser, const char *buf, size_t len)
{
	assert(parser!=NULL);
	//printf("header_value_cb\n");
	printf("header_value_cb %d %.*s\n", (int)len, (int)len , buf);
	
	http_request_t *http_request = parser->data;
	//http_request->header_lines++;
		
	http_request->header_value[http_request->header_lines -1]= strndup(buf, len);
	
	
	
	return 0;
}

int on_header_complete_cb(http_parser *parser)
{
	assert(parser!=NULL);
	//printf("header_value_cb\n");
	printf("on_header_complete_cb\n");
	
    http_request_t *http_request = parser->data;

    const char *method = http_method_str((enum http_method)parser->method);

    http_request->method = strdup(method);
	
	return 0;
}

int on_body_cb(http_parser *parser/*parser*/, const char *at, size_t length) 
{
    printf("on_body_cb: %.*s", (int) length, at);
	
    http_request_t *http_request = parser->data;

    http_request->body = strndup(at , length );

    return 0;
}

/* 
static http_parser_settings settings =
  {.on_message_begin = message_begin_cb
  ,.on_header_field = header_field_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = response_status_cb
  ,.on_body = body_cb
  ,.on_headers_complete = headers_complete_cb
  ,.on_message_complete = message_complete_cb
  };
  */
static http_parser_settings settings =
  {.on_message_begin = message_begin_cb
  ,.on_header_field = header_field_cb
  ,.on_header_value = header_value_cb
  ,.on_url = request_url_cb
  ,.on_status = 0
  ,.on_body = on_body_cb
  ,.on_headers_complete = on_header_complete_cb
  ,.on_message_complete = 0
  };
  
struct http_parser parser ;



int test(const char* req)
{
	int nread = strlen(req);
	http_request_t  request;

	memset(&request, 0 , sizeof(request));
	
	memset(&parser, 0 ,sizeof(parser));
	
	
	
	parser.data = &request ;
	
	int parsed , i ;
	http_parser_init(&parser, HTTP_REQUEST);
	
	for (i = 0 ; i < nread; i++)	
	{
		
		parsed=  http_parser_execute( &parser, &settings, req+i, 1);
		if (parsed < 1) 
		 {
			printf("parser error %d %d", parsed, nread );
		 }
	}	
	
	 
	 
	 printf("request url %s method %s body %s\n", request.url, request.method, request.body );
	 
	
	 for (i=0 ; i < request.header_lines ; i++ )
	 {
		printf("header %s - %s\n", request.header_field[i], request.header_value[i]);
	 }
	 return 0; 
	
}

int main()
{
	const char* req1 = "GET /favicon.ico HTTP/1.1\r\n"
         "Host: 0.0.0.0=5000\r\n"
         "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\n"
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
         "Accept-Language: en-us,en;q=0.5\r\n"
         "Accept-Encoding: gzip,deflate\r\n"
         "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
         "Keep-Alive: 300\r\n"
		 "Content-Length: 6\r\n"
         "Connection: keep-alive\r\n"
         "\r\n"
		 "123456\r\n";
						
						
	test(req1);
	return 0;
}