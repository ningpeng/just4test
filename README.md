一些 个人库  just for test


 
#### runtime_config.c/h   读取ini配置文件 ,   用法见单元测试代码
 
#### stringex.c/h      一些增强 字符串函数 , 用法见单元测试代码

    size_t _strlcpy(char *  dst, const char *  src, size_t dsize);
    size_t _strlcat(char *  dst, const char *  src, size_t dsize);
    char*  _strnstr(const char *s, const char *find, size_t slen);
    char * _strnsep(char **stringp, const char *delim, int size);
    size_t _strn_cspn (const char *s, const char *reject , int s_size);

char * _strnstr(const char *s, const char *find, size_t slen);
const char * _strstrn(char *s1, char *s2, size_t s2_len);

 
#### pn_str
一种 字符串指针 + 长度的结构,  以及附带的一系列函数,  用于字符串解析比如 url token 之类的很有用
