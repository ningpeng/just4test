
#include "stringex.h"
#include <string.h>
/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
_strlcpy(char *  dst, const char *  src, size_t dsize)
{
        const char *osrc = src;
        size_t nleft = dsize;

        /* Copy as many bytes as will fit. */
        if (nleft != 0) {
                while (--nleft != 0) {
                        if ((*dst++ = *src++) == '\0')
                                break;
                }
        }

        /* Not enough room in dst, add NUL and traverse rest of src. */
        if (nleft == 0) {
                if (dsize != 0)
                        *dst = '\0';            /* NUL-terminate dst */
                while (*src++)
                        ;
        }

        return(src - osrc - 1); /* count does not include NUL */
}


/*
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 */
size_t
_strlcat(char *  dst, const char *  src, size_t dsize)
{
        const char *odst = dst;
        const char *osrc = src;
        size_t n = dsize;
        size_t dlen;

        /* Find the end of dst and adjust bytes left but don't go past end. */
        while (n-- != 0 && *dst != '\0')
                dst++;
        dlen = dst - odst;
        n = dsize - dlen;

        if (n-- == 0)
                return(dlen + strlen(src));
        while (*src != '\0') {
                if (n != 0) {
                        *dst++ = *src;
                        n--;
                }
                src++;
        }
        *dst = '\0';

        return(dlen + (src - osrc));    /* count does not include NUL */
}




//自己修改的 _strnsep ,  size 用来描述 *stringp 的大小
//当达到字符串限定长度或者字符结束的时候,  返回tok, stringp* = NULL
char * _strnsep(char **stringp, const char *delim, int size)
{
        char *s;
        const char *spanp;
        int c, sc;
        char *tok;
        int len = 0; //size=1000;

        if ((s = *stringp) == NULL)
                return (NULL);

        for (tok = s; len<size ; len++) {
                c = *s++;
                spanp = delim;
                do {
                        if ((sc = *spanp++) == c) {
                                if (c == 0)
                                        s = NULL;
                                else
                                        s[-1] = 0;
                                *stringp = s;
                                return (tok);
                        }
                } while (sc != 0);
        }
        /* NOTREACHED */
        
        *stringp = NULL;
        
        return tok;
}

/* Return the length of the maximum initial segment of S
   which contains no characters from REJECT.  */
size_t _strn_cspn (const char *s, const char *reject , int s_size)
{
  size_t count = 0;

  while (*s != '\0' && count<s_size)
    if (strchr (reject, *s++) == NULL)
      ++count;
    else
      return count;

  return count;
}

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char * _strnstr(const char *s, const char *find, size_t slen)
{
        char c, sc;
        size_t len;

        if ((c = *find++) != '\0') {
                len = strlen(find);
                do {
                        do {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                        return (NULL);
                        } while (sc != c);
                        if (len > slen)
                                return (NULL);
                } while (strncmp(s, find, len) != 0);
                s--;
        }
        return ((char *)s);
}

//search s2 (size s2_len limited) in s1
// 在一个字符串中是否有子指定大小的字符串
const char * _strstrn(char *s1, char *s2, size_t s2_len)
{
    char  c1, c2;

    c2 = *(char *) s2++;

    do {
        do {
            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

    } while (strncmp(s1, (char *) s2, s2_len) != 0);

    return --s1;
}

