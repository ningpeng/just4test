#define _BSD_SOURCE
#define _XOPEN_SOURCE        /* or any value < 500 */

#include <stdio.h>
#include <stddef.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "stringex.h"

#include "pnx_str.h"



//将px_str_t 附着在一个char buf[] 上面
int pnx_str_attach(pnx_str_t *str, char* src)
{
	str->data = src;
	str->len = strlen(src);
	return str->len ;
}

pnx_str_t*  pnx_str_new(const char* src)
{
	
	pnx_str_t* str = malloc(sizeof(pnx_str_t));
	str->data = strdup(src);
	str->len = strlen(src);
	return str;

}

void pnx_str_free(pnx_str_t *str)
{
	free(str->data);
	free(str);
}

//打印pnx_str_t 结构, 仅供调试
void pnx_str_print(const pnx_str_t *str)
{
	if (NULL==str)
	{
		printf("NULL str point\n");
		return;
	}

	if (NULL==str->data)
	{
		printf("pnx_str_t %p len %d ->data NULL pointer\n", str, str->len);
		return ;
	}

	printf("pnx_str_t %p %d:%.*s\n", str, str->len, str->len, str->data);

}

//假如 data 指针 == NULL 则为空
//字符串长度为0 则字符串是非空的
int pnx_str_isnull(const pnx_str_t *str)
{
	//pnx_str_print(str);

	if (str==NULL)
	{
		return 1;
	}

	if (NULL==str->data )
	{
		return 1;
	}
	return 0;
}

pnx_str_t pnx_str_split(const pnx_str_t *src,  const char* delim, pnx_str_t *str_2nd)
{
	pnx_str_t ret_str = pnx_null_string;

	if (pnx_str_isnull(src))
	{
		str_2nd->len = 0;
		str_2nd->data = NULL;
		return ret_str;
	}	

	int len = _strn_cspn( src->data, delim, src->len);

	assert(len <= src->len );

	if (len<src->len) //found delim
	{
		ret_str.data = src->data;
		ret_str.len = len;
		
		str_2nd->data = src->data + len + 1;
		str_2nd->len = src->len - len - 1;
	}
	else //not found
	{
		ret_str = *src ;

		str_2nd->data = NULL;
		str_2nd->len = 0;
	}	

	return ret_str;

}

//strsep的pnx_str_t版本
//写错了!  _strnsep 会写入0
pnx_str_t pnx_strsep_wrong(pnx_str_t *stringp,  const char* delim)
{
	char *strp = stringp->data;
	pnx_str_t ret  = { 0 , NULL };


	char* r = _strnsep( &strp , delim, stringp->len );
	

	printf("strnsep (%p -> %p, %s , %d) ret %p\n", stringp->data, strp, delim, stringp->len, r );

	
	if (r) //found the delim
	{
		ret.data = r ;
		if (strp) //found the delim
		{
			ret.len = strp - stringp->data -1;
			
		}
		else // reach the end
		{
			ret.len = stringp->len;
		}
	}
	
	if (NULL==strp)
	{
		stringp->len = 0;
	}
	else
	{
		stringp->len = stringp->len - (strp - stringp->data);
	}
	stringp->data = strp;

	return ret;
}

//strcmp 的 pnx_str_t 版本
int pnx_strcmp(const pnx_str_t *str1, const char *s2 )
{
	int ret =  strncmp(str1->data, s2, str1->len);

	if (ret==0 && s2[str1->len]!=0)
		return -1; //strlen(s2) is greater than str1

	return ret;

}




//from pnx_str_t copy string to buffer
size_t pnx_str_cp2buf(char* dst, size_t size , const pnx_str_t *src)
{
        if (src->len < size)
        {
                memcpy(dst, src->data, src->len);
                dst[src->len] = '\0' ;
                return src->len;
        }
        else
        {
                //buffer can't hold the src string
                memcpy( dst, src->data, size - 1 );
                dst[size-1] = '\0';
                return size - 1;
        }
        
}


