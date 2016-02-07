
#ifndef LIBBSD_STRING_H
#define LIBBSD_STRING_H

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

__END_DECLS

#endif

