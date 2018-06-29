#ifndef __UTILS_H
#define __UTILS_H
#include <sys/cdefs.h>
__BEGIN_DECLS

#define CDNLOG_FL_COMMON                        0
#define CDNLOG_FL_MSG                           1
#define CDNLOG_FL_RDNCY                         2
#define CDNLOG_FL_DB                            3

#define CDNLOG_FL_USER0                         4
#define CDNLOG_FL_USER1                         5
#define CDNLOG_FL_USER2                         6

#ifndef CDNLOG_LV_ERROR
        #define CDNLOG_LV_ERROR                         0x8000
#endif
#ifndef CDNLOG_LV_WARNING
        #define CDNLOG_LV_WARNING                       0x4000
#endif
#ifndef CDNLOG_LV_INFO
        #define CDNLOG_LV_INFO                          0x2000
#endif
#ifndef CDNLOG_LV_TRACE
        #define CDNLOG_LV_TRACE                         0x1000
#endif

#define CDNLOG_LV_ALL_MASK  (CDNLOG_LV_ERROR|CDNLOG_LV_WARNING|CDNLOG_LV_INFO|CDNLOG_LV_TRACE)

#define CDNLOG_LV_EN_INFO (CDNLOG_LV_ERROR|CDNLOG_LV_WARNING|CDNLOG_LV_INFO)
#define CDNLOG_LV_DEFAULT  CDNLOG_LV_EN_INFO

int util_set_log_mask(int mask);
int daemonize(const char*  fname);
int print_log(int flow, int level,  const char *fmt, ...);
void print_version_info(const char *name);


/**
 * @brief get_executable_path ��ȡlinux�³���·���Ϳ�ִ���ļ���
 *
 * @param input processdir ��ſ�ִ���ļ�Ŀ¼
 * @param input processname ��ſ�ִ���ļ��ļ���

 *
 * @return ��ִ��·���ĳ��� 
 */
int get_executable_path( char* processdir, int dir_len,  char* exe_name, int file_len); 


#define log_trace(s...)  print_log(CDNLOG_FL_COMMON, CDNLOG_LV_TRACE , ##s)
#define log_info(s...)  print_log(CDNLOG_FL_COMMON, CDNLOG_LV_INFO , ##s)
#define log_warn(s...)  print_log(CDNLOG_FL_COMMON, CDNLOG_LV_WARNING , ##s)
#define log_err(s...)   print_log(CDNLOG_FL_COMMON, CDNLOG_LV_ERROR, ##s)

#define FUNC_UTRACE  log_info(  "===trace=== %s():%d\r\n"  , __FUNCTION__, __LINE__);

__END_DECLS
#endif
