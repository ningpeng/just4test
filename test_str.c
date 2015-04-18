#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct {
    size_t      len;
    char 	    *data;
} pnx_str_t;

#define pnx_string(str)     { sizeof(str) - 1, (u_char *) str }

#define pnx_null_string     { 0, NULL }

#define pnx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text

#define pnx_str_null(str)   (str)->len = 0; (str)->data = NULL


int pnx_strcmp(const pnx_str_t *str1, const char *s2 )
{
	int ret =  strncmp(str1->data, s2, str1->len);

	if (ret==0 && s2[str1->len]!=0)
		return -1; //strlen(s2) is greater than str1

	return ret;

}

/*** function returns a pointer to a new string which is a duplicate of the string s.  Memory for the
*       new string is obtained with malloc(3), and can be freed with free(3).
***/
char* pnx_strdup(const pnx_str_t *str)
{
	return strndup( str->data, str->len);
}

//LIKE strlcpy in BSD . return the length of src. if size <= src, the dst is not equal to src
size_t _strlcpy(char *dst, const char *src, size_t size)
{
    size_t len = 0;
    while (++len < size && *src)
        *dst++ = *src++;
    if (len <= size)
        *dst = 0;
    return len + strlen(src) - 1;
}

size_t pnx_strcpy2buf(char* dst, size_t size , const pnx_str_t *src)
{
	if (src->len < size)
	{
		memcpy(dst, src->data, src->len);
		dst[src->len] = '\0' ;
	}
	else
	{
		//buffer can't hold the src string
		memcpy( dst, src->data, size - 1 );
		dst[size-1] = '\0';
	}
	return src->len;
}

char *pnx_strstr(const pnx_str_t *str, char *sub)
{
	char *buf = str->data;
	char *buf_end = buf + str->len;

	register char *bp;
	register char *sp;

    if (!*sub)
		return buf;
    while (*buf) {
		bp = buf;
		sp = sub;
		do {
			if (!*sp)
				return buf;
			if (bp >= buf_end)
				return 0;
		} while (*bp++ == *sp++);
		buf += 1;
    }
    return 0;
}

/***
* locates  the  first occurrence in the string s of any of the characters in the string
       accept. and return a pnx_str_t value which store the string before the accept
***/
pnx_str_t pnx_split_1st(char *s, const char *accept)
{
	pnx_str_t ret = pnx_null_string;
	char *off = strpbrk(s, accept);

	if (off==NULL)
		return ret;

	ret.data = (char*)s;
	ret.len = off - s;

	return ret;
}

int str_replace(const char* s1, const char* substr, const char* replacement, char* out, size_t size)
{
	
	const char *index_old = s1 , *index;
	int sub_len = strlen(substr);
	int rep_len = strlen(replacement);
	int  copy_len = 0;
	int  len =0;
	char quit_flag = 0;
	
	if (size <=0)
		return 0;
		
	while (index = strstr(index_old, substr))
	{
		len = index - index_old; 	
		
		if (copy_len + len >=size)
		{
			len = size - copy_len - 1;
			out[size-1] = '\0';
			quit_flag = 1;
		}		
		memcpy(out + copy_len, index_old, len);
		copy_len += len;
		
		if (quit_flag)
			break;
		
		if (copy_len + rep_len >=size )
		{
			rep_len = size - copy_len - 1;
			out[size-1] = '\0';
			quit_flag = 1;
		}
		memcpy(out + copy_len, replacement, rep_len);
		copy_len += rep_len;
		if (quit_flag)
			break;
		
		index_old = index + sub_len;
	}
	
	if (!quit_flag)
	{
		//copy the end of string
		copy_len+= _strlcpy( out + copy_len , index_old, size - copy_len );
		
	}
	return copy_len;
	
}

void test1()
{
	pnx_str_t str = {5, "0123456789abcdefg"};

	printf("%s\n", pnx_strstr( &str, "34"));
	printf("%s\n", pnx_strstr( &str, "12"));
	printf("%s\n", pnx_strstr( &str, "23"));

	assert( 0 == pnx_strstr( &str, "345"));
	assert( 0 == pnx_strstr( &str, "45"));
	assert( 0 == pnx_strcmp(&str, "01234"));

	printf("%d %d\n", pnx_strcmp(&str, "012345"), strcmp("01234", "012345"));
}

int test2()
{

    int len, nel;

    char query[] ="user_command=appleboy&test=1&test2=2";

    char *q, *name, *value;

    /* Parse into individualassignments */

    q = query;

    fprintf(stderr, "CGI[query string] : %s\n",query);

    len = strlen(query);

    nel = 1;

    while (strsep(&q, "&"))

        nel++;

    fprintf(stderr, "CGI[nel string] : %d\n", nel);

    for (q = query; q< (query + len);) {

        value = name = q;

        /* Skip to next assignment */

        fprintf(stderr, "CGI[string] :%s\n", q);

        fprintf(stderr, "CGI[stringlen] : %d\n", strlen(q));

        fprintf(stderr, "CGI[address] :%x\n", q);

        for (q += strlen(q); q < (query +len) && !*q; q++);

        /* Assign variable */

        name = strsep(&value,"=");

        fprintf(stderr, "CGI[name ] :%s\n", name);

        fprintf(stderr, "CGI[value] :%s\n", value);

    }

    return 0;

}

int test3()
{
	char str[] = "abcdefgdhig";
	char *p = str;
	char *key_point;
	while(p)
	{
		while(key_point=strsep(&p,"cd")){
			printf("%c\n", *p);
			
			if (*key_point==0)
				continue;	//遇到连续的关键字，返回一个指向\0的指针，继续往后找就是
			else
				break;//分割出一个正常的字符串，快去打印吧！
		}
		printf("%s\n",key_point);
	}
}

int test4()
{
	char buf[64] = {0};
	
	char str[] = "01234567890abc90defghij90kl";
	
	str_replace(str, "345", "<!@#$%>", buf, 64 ); printf("%s\n" , buf );
	str_replace(str, "345", "<!@#$%>", buf, 12 ); printf("%s\n" , buf );
	int i = 64;
	for (;i>=0; i--)
	{
		str_replace(str, "90", "<abcde>", buf, i  ); printf("%d , %s\n" , i , buf );
		assert( strlen(buf) <= i-1 );
	}

}
main()
{
	test1();
	//test2();
	//test3();
	test4();
    return 0;
}
