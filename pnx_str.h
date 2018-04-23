
#ifndef LIB_PNX_STRING_H
#define LIB_PNX_STRING_H

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

#define PNX_MAX(a,b)  ((a)>(b)?(a):(b))
#define PNX_MIN(a,b)  ((a)>(b)?(b):(a))


typedef struct _pnx_str_t{
    int      	len;	//site_t in x64 is 8bytes , so use 4byte int , and %.*s expect int 
    char 	*data;
} pnx_str_t;

//usage: pnx_str_t str = pnx_string("aaaaa");
#define pnx_string(str)     { sizeof(str) - 1, (char *) str }

//usage: pnx_str_set(str, "asdfafd") ; //pnx_str_t str;
//wrong: const char* p = "aaa" ; pnx_str_set(str, a);
#define pnx_str_set(str, text)    do {                                          \
    (str)->len = sizeof(text) - 1; (str)->data = (char*) (text) } while(0)

//usage: pnx_str_t str = pnx_null_string ;
#define pnx_null_string     { 0, NULL }

//usage: pnx_str_set_null(str); //pnx_str_t str; 
#define pnx_str_set_null(str)   do { \
    (str)->len = 0; (str)->data = NULL; }while(0) 



//将px_str_t 附着在一个char buf[] 上面
int pnx_str_attach(pnx_str_t *str, char* src);

//根据str创建一个 pnx_str_t, 使用完毕需要pnx_str_free
pnx_str_t*  pnx_str_new(const char* str);

//释放 pnx_str_new()创建的 pnx_str_t * ,  
void pnx_str_free(pnx_str_t *str);

//打印pnx_str_t 结构, 仅供调试
void pnx_str_print(const pnx_str_t *str);

//假如 data 指针 == NULL 则为空
//字符串长度为0 则字符串是非空的
int pnx_str_isnull(const pnx_str_t *str);

//strsep的pnx_str_t版本,目前实现有问题
pnx_str_t pnx_strsep(pnx_str_t *stringp,  const char* delim);

//将 src 依靠 delim中的任意字符 分割为两个字符串, 左边为返回值, 右边为str_2nd
//假如delim中字符没有找到, 那么str_2nd为空
//假如 那么str_2nd为空 , 那么返回为空
//src 和 str_2nd 可以为同个字符串, 但是这样返回后 src 的内容会被改动
pnx_str_t pnx_str_split(const pnx_str_t *src,  const char* delim, pnx_str_t *str_2nd);

//strcmp 的 pnx_str_t 版本
int pnx_strcmp(const pnx_str_t *str1, const char *s2 );

//from pnx_str_t copy string to buffer
size_t pnx_str_cp2buf(char* dst, size_t size , const pnx_str_t *src);

__END_DECLS

#endif