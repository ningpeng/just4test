
#ifndef LIB_STRINGEX_H
#define LIB_STRINGEX_H

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

size_t _strlcpy(char *  dst, const char *  src, size_t dsize);
size_t _strlcat(char *  dst, const char *  src, size_t dsize);
char*  _strnstr(const char *s, const char *find, size_t slen);
char * _strnsep(char **stringp, const char *delim, int size);
size_t _strn_cspn (const char *s, const char *reject , int s_size);

char * _strnstr(const char *s, const char *find, size_t slen);
const char * _strstrn(char *s1, char *s2, size_t s2_len);
__END_DECLS

#endif