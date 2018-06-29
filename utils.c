#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <syscall.h>
#include <sys/time.h>

#include "utils.h"

#ifndef _POSIX_VERSION
#error "only for POSIX SYSTEM (linux)"
#endif

char * getTimeStr(char *str, int len)
{
    struct tm *t, tbuf;
    time_t tsec;

    time(&tsec);
    t = localtime_r(&tsec, &tbuf);
    snprintf(str, len, "%02d-%02d-%02d:%02d:%02d:%02d", t->tm_year-100, t->tm_mon+1,
             t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    return str;

}

static void config_change(int dummy)
{
    update_configuration(); //in runtime_config.c
}

void cleanup(int dummy)
{
    static int called = 0;
    if (!called)
    {
        fflush(stdout);
        print_log(CDNLOG_FL_COMMON,CDNLOG_LV_INFO,"Signal %d received, Flush stdout and quit\n", dummy);
        called = 1;
        //sys_set_exit_flag();/* DISK_MONITOR */      
        exit(1);
    }
    //program_exit = 1;
    //pthread_exit((void*) 0);
}

void registerSignals(void)
{

    printf("register signals\n")
    (void) signal(SIGHUP, config_change);
    (void) signal(SIGINT, cleanup);
    (void) signal(SIGQUIT, cleanup);
    //(void) signal(SIGILL, cleanup);
    //(void) signal(SIGTRAP,cleanup);
    (void) signal(SIGIOT,cleanup);
    //  (void) signal(SIGEMT,cleanup);
    //(void) signal(SIGFPE,cleanup);
    //(void) signal(SIGBUS,cleanup);
    //(void) signal(SIGSEGV,cleanup);
    (void) signal(SIGSYS,cleanup);
    (void) signal(SIGPIPE,SIG_IGN);
    //  (void) signal(SIGALRM,cleanup);
    (void) signal(SIGTERM,cleanup);

}

int daemonize(int need_chdir, int noclose, const char* log_file)
{
    int fd;
    struct stat statbuf;
    char mvfname[256];
    char time_str[100];

    switch (fork()) {
        case -1: return -1;
        case 0:  break;
        default: _exit(0);
    }
    if (setsid()==-1) 
        return -1;
    
    if (noclose) 
        return 0;

    if (need_chdir)
        chdir("./");

    registerSignals();

    if (stat(log_file, &statbuf) != -1)
    {   // log file exists. rename it
        sprintf(mvfname, "%s-%s", log_file , getTimeStr(time_str, sizeof(time_str)));
        if (rename(log_file, mvfname) != -1)
        {
                printf("Renamed %s to %s\n", log_file, mvfname);
        }
        else
        {
                
                printf("Failed to rename %s to %s. %s.\n",
                    log_file, mvfname, strerror(errno));
        }
    }

        
    fd=open(log_file, O_CREAT|O_RDWR|O_APPEND, 0);
    if (fd!=-1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd>2) close(fd);


        //fd=  open("/var/log/dsim.log" ,O_CREAT|O_RDWR|O_APPEND,0660);     
        //dup2(fd, STDOUT_FILENO);
        
    }
    else
    {
        printf("open log err %s\n", strerror(errno));
        exit(1);
    }
    printf("daemon...done\n");
    
    return 0;
}

const char *logPrefix[3] =
{
    " ",
    " [ERROR]: ",
    " [WARNING]: "
};

volatile int logSize = 0;

int print_log(int flow, int level,  const char *fmt, ...)
{
    int r;
    
    struct tm *t, tbuf;
    struct timeval t_currentTime;
    va_list ap;
    const char *prefix;

    char log_line[1024];

    if ((level & CDNLOG_LV_MASK) == 0)
        return 0;
    
    if ((level & CDNLOG_LV_ERROR) != 0)
    {
        prefix = logPrefix[1];
    }
    else if ((level & CDNLOG_LV_WARNING) != 0)
    {
        prefix = logPrefix[2];
    }
    else
    {
        prefix = logPrefix[0];
    }

    va_start(ap, fmt);

    gettimeofday(&t_currentTime, (struct timezone *)0);

    if (t_currentTime.tv_usec < 0)
    {
        t_currentTime.tv_sec--;
        t_currentTime.tv_usec += 1000000;
    }
    else if (t_currentTime.tv_usec >= 1000000)
    {
        t_currentTime.tv_sec++;
        t_currentTime.tv_usec -= 1000000;
    }


    t = localtime_r(&(t_currentTime.tv_sec), &tbuf);

    r = sprintf( log_line, "%02d%02d%02d-%02d%02d%02d.%06d-%ld%s",
           t->tm_year-100, t->tm_mon+1,
           t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
           (unsigned int)(t_currentTime.tv_usec), syscall(SYS_gettid), prefix);

    //logSize += r;

    vsnprintf(log_line+r , sizeof(log_line)-r, fmt, ap);
    
    //r = vprintf(fmt, ap);
    printf( "%s", log_line );

    logSize += r;
        
    va_end(ap);

    if (logSize>512*1024)
    {
        //fflush(stdout);
        //logSize = 0;
    }
    return r;
}