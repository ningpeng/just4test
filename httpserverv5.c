//gcc -o dsim httpserverv5.c -lpthread -g -Wall

//writen by ning 2012.11.26
// 2015-4   增加匀速发送文件测试

#define _GNU_SOURCE


#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <poll.h>
#include <sys/sendfile.h>
#include <sys/select.h>
#include <signal.h>


//#define __x86_64__
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 

typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(i)  { (i) }

#define LOCK_PREFIX "lock ; "
static inline int atomic_read(const atomic_t *v)
{
        return (*(volatile int *)&(v)->counter);
}
static inline void atomic_inc(atomic_t *v)
{
        asm volatile(LOCK_PREFIX "incl %0"
                     : "+m" (v->counter));
}
static inline void atomic_dec(atomic_t *v)
{
        asm volatile(LOCK_PREFIX "decl %0"
                     : "+m" (v->counter));
}


/**********************************************************************************************************/
struct obj_map
{
	char			    obj_id[256];
	char				uri[256];
};

#define MAX_OBJMAP_NUM 58000

typedef unsigned uid_type_t;

struct obj_mem
{
	struct obj_map 	obj_map_list[MAX_OBJMAP_NUM];
	uid_type_t 		id_list[MAX_OBJMAP_NUM];
	int			   	obj_map_num ;

	int				start_index[10];
};


struct obj_mem g_local ;
struct obj_mem g_cache ;

/**********************************************************************************************************/
typedef struct 
{
	// you must use lock by yourself
	int element_num; //the arry queue size
	int head;  //if (head == tail) , queue is empty
	int tail;  //if (tail == head-1) , queue is full
} queue_cb;

//
void init_queue(queue_cb *qcb, int element_num)
{
	qcb->head = qcb-> tail = 0;
	qcb->element_num = element_num ;
}

int get_queue_count(queue_cb *qcb)
{
	return (qcb->tail + qcb->element_num -qcb->head) % qcb->element_num;
}

// 0 is not empty
int is_queue_empty(queue_cb *qcb)
{
	return (qcb->head==qcb->tail);
}
// 0 is not full
int is_queue_full(queue_cb *qcb)
{
	return ((qcb->tail + 1) % qcb->element_num == qcb->head );
}

//return >=0 , the index of the queue tail element
int en_queue(queue_cb *qcb)
{
	int old_tail = qcb->tail;

	int ptr = (old_tail + 1) % qcb->element_num;

	if (ptr==qcb->head)
	{
		//queue full
		return -1; 
	}
	qcb->tail =  ptr;
	return old_tail;
}

//return >=0 , the index of the queue head element
int de_queue(queue_cb *qcb)
{
	if ( is_queue_empty(qcb) )
	{
		//empty queue
		return -1;
	}
	
	int old_head = qcb->head;
	qcb->head = (old_head + 1)%qcb->element_num;

	return old_head;

}
/**********************************************************************************************************/
typedef struct 
{
	int		sock;
	int		file_fd;
	off_t 	read_pos;	//readed position
	struct  timeval start_tv;
	//struct  timeval next_send_tv;
} 
http_req_cb;


http_req_cb todo[1024];

queue_cb todo_cb;

static pthread_mutex_t cb_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;


#define MAX_STREAM_PERTHREAD 4096





/**********************************************************************************************************/

#ifndef WIN32

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


#define LOG_FILE "/dev/shm/dsim.log"
//#define LOG_FILE_ROTATE "/var/log/dsim.log"
#define LOG_FILE_ROTATE LOG_FILE

int daemon(int nochdir, int noclose)
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
	if (setsid()==-1) return -1;
	if (noclose) return 0;


	if (stat(LOG_FILE, &statbuf) != -1)
    {   // log file exists. rename it
        sprintf(mvfname, "%s-%s", LOG_FILE_ROTATE , getTimeStr(time_str, sizeof(time_str)));
        if (rename(LOG_FILE, mvfname) != -1)
		{
	            printf("Renamed %s to %s\n", LOG_FILE, mvfname);
		}
		else
		{
	            
				printf("Failed to rename %s to %s. %s.\n",
			       	LOG_FILE, mvfname, strerror(errno));
		}
    }

		
	fd=open(LOG_FILE, O_CREAT|O_RDWR|O_APPEND, 0);
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
#endif

char *logPrefix[3] =
{
    " ",
    " [ERROR]: ",
    " [WARNING]: "
};
/********* LOG MARCO REDEFINED*************/

#define RSSLOG_LV_ERROR                         0x8000
#define RSSLOG_LV_WARNING                       0x4000
#define RSSLOG_LV_INFO                          0x2000
#define RSSLOG_LV_TRACE                         0x1000


//#define RSSLOG_LV_MASK 	(RSSLOG_LV_ERROR|RSSLOG_LV_WARNING|RSSLOG_LV_INFO)
#define RSSLOG_LV_MASK 	(RSSLOG_LV_ERROR|RSSLOG_LV_WARNING|RSSLOG_LV_INFO|RSSLOG_LV_TRACE)

volatile int logSize = 0;


#define TRACE printf
//#define TRACE

int print_log(int level,  char *fmt, ...)
{
    int r;
	
    struct tm *t, tbuf;
    struct timeval t_currentTime;
    va_list ap;
    char *prefix;

	char log_line[1024];

	if ((level & RSSLOG_LV_MASK) == 0)
		return 0;
	
    if ((level & RSSLOG_LV_ERROR) != 0)
    {
        prefix = logPrefix[1];
    }
    else if ((level & RSSLOG_LV_WARNING) != 0)
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

char* safe_strncpy(char* dst, const char* src, size_t size) 
{
	//assert((dst!=NULL) && (src!=NULL));
	char* retAddr = dst;		/**< retAddr is in static , char retAddr[] will in Stack, So... */	 
	int i = 0;		
	while (((*(dst++) = *(src++))!='\0') && ((i++) < size)) 
		{ 		  ;	 }
	*(retAddr+size-1)='\0';		/**< cut off String  */
	return retAddr;
}

#define RW_MAX_TTL 16

static ssize_t writen_ex(int fd, const void *buf, size_t size, int ms)
{
    ssize_t offset = 0, left = size, len;
    int ttl = RW_MAX_TTL;
    struct pollfd pfd;
    int i;
	
    while (left > 0) {
        pfd.fd = fd;
        pfd.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
        errno = 0;
        i = poll(&pfd, 1, ms);
        if (i < 0)
        {
            if (errno == EINTR){
                if (--ttl<=0) {
                    fprintf(stdout, "[writen_ex] ERROR: writen poll ttl overflow, errno:%d size:%lu\n" , errno, size);      
                    return -6;
                }
                continue;
            }
            
			fprintf(stdout, "[writen_ex]: writen errno:%d\n" , errno  );
            return -1;  // error
        } else if (0==i) {
            fprintf(stdout, "[writen_ex]: writen poll timeout\n" );
            return -2;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            fprintf(stdout, "[writen_ex] ERROR: writen err revents:%x errno:%d len:%lu\n" , pfd.revents, errno, size); 
            return -3;
        }
        
        len = write(fd, (char*)buf + offset, left);
        if (len < 0)
        {
            if (errno == EINTR){
                if (--ttl<=0) {
                    fprintf(stdout, "[BMDP]: writen write ttl overflow:%d\n" , errno);      
                    return -6;
                }
                continue;
            }
            return -4;
        }
        offset += len;
        left -= len;
    }
    return offset;
}

static ssize_t writen(int fd, const void *buf, size_t size )
{
    return writen_ex( fd, buf ,size , 2000);
}

static int read_time(int fd, void *buf, int size, int ms)
{
    ssize_t  len = 0;
    int ttl = RW_MAX_TTL ;
    struct pollfd pfd;
    int i;
    while (1) {
        pfd.fd = fd;
        pfd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
        errno = 0;
        i = poll(&pfd, 1,  ms );
        if (i < 0)
        {
            if (errno == EINTR){
                if (--ttl<=0) {
                    fprintf(stdout, "[readn_ex] ERROR: readn poll ttl overflow, errno:%d size:%d\n" , errno, size); 
                    return -6;
                }
                continue;
            }
            fprintf(stdout, "[readn_ex]: readn errno:%d\n" , errno );
            return -1;  // error
        } 
		else if (0==i) {
            fprintf(stdout, "[readn_ex]: readn poll timeout\n" );
            return -2;
        }
        
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
        {
            fprintf(stdout, "[readn_ex] ERROR: readn err revents:%x errno:%d len:%d\n" , pfd.revents, errno, size); 
            return -3;
        }
        len = read(fd, (char*)buf, size);
        if (len < 0)
        {
            if (errno == EINTR){
                if (--ttl<=0) {
                    fprintf(stdout, "[readn_ex] ERROR: readn poll ttl overflow, errno:%d size:%d\n" , errno, size); 
                    return -6;
                }
                continue;
            }
            return -4;
        }
        if (len == 0)  //EOF ,is return -5 right???
		{
			fprintf(stdout, "[readn_ex] EOF\n");
            return -5;
		}
		return len;

    }
    return -1;
}

static int stable_send(int fd, const char *buf,int size, int* sended_bytes) {
	int ret;
	
	if (sended_bytes)
		*sended_bytes = 0;

    while(size > 0) {
		 /* ret = send(fd, buf, size, 0 | MSG_NOSIGNAL);   replaced by coming.ling */
		ret = write(fd, buf, size);

		if(ret < 0) 
	 	{
	        printf(" stable_send sock %d ERR %d:%s\n", fd, ret, strerror(errno));
	        return -1;
	    }
		else if (ret==0)
		{	
			printf("stable_send sock %d EOF %d\n", fd, ret);
			return 0;
		}
		if (sended_bytes)
			*sended_bytes += ret;
		
        buf += ret;
        size -= ret;
	}
    return 1;
}

/*
//璇诲彇鍥炲簲锛岀洿鍒拌鍒?\r\n\r\n 涓烘
static int read_response( int sockfd , void* buf , int len )
{
	int ret ;
	int byte_sum = 0;
	char* p = (char*)buf;
	int ttl = RW_MAX_TTL;

	
	while((ret = read_time( sockfd , p , len , 500 ))>0 && ttl-->0) //500ms timeout
	{
		if( ret <= 0 )
		{
			//PTRACE("read_time ret %d\n", ret);
			return ret;
		}
		p+=ret;
		byte_sum+=ret;


		if( byte_sum >= len )
			break;

		if (NULL!=strstr((const char*)buf, "\r\n\r\n"))
		{
			//PTRACE("--read response end flag\n");
			break;
		}
	}
	return byte_sum;
}
*/

#if 0
#define LOCK_PREFIX "lock ; "

typedef struct { volatile int counter; } atomic_t;

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.
 */ 
static __inline__ void atomic_inc(atomic_t *v)
{
		__asm__ __volatile__(
				LOCK_PREFIX "incl %0"
				:"=m" (v->counter)
				:"m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static __inline__ void atomic_dec(atomic_t *v)
{
		__asm__ __volatile__(
				LOCK_PREFIX "decl %0"
				:"=m" (v->counter)
				:"m" (v->counter));
}

#endif


#define BUFFER_INIT_SIZE 640

enum {
    pn_reading_header_stage,
	pn_continue_reading_header_stage,
	pn_d11_request_stage,
	pn_d11_response_stage,
    pn_writing_header_stage,
    pn_writing_body_stage,
    pn_writing_body_stage_thread,
    pn_closing_stage
};

enum {
    pn_http_ok,
    pn_http_notfound,
    pn_http_302,
    pn_http_201,
    pn_http_200,
    pn_http_error
};

enum {
    pn_method_get = 1,
	pn_method_post =2 ,
    pn_method_head =3 ,
    pn_method_unknow =4
};

typedef struct {
    char *buff;
	char init_buf[BUFFER_INIT_SIZE];
    int  size;
    int  free;
} pn_buffer_t;

typedef struct {
    int sock;
	int sock_d11;
    pn_buffer_t *request;
    pn_buffer_t *response;
	pn_buffer_t *d11_response;
    int keepalive;
    int method;
    pn_buffer_t *uri;
	char		host[64];
    int status;
    int stage;
    int handle_fd;
	pn_buffer_t req_init;
	pn_buffer_t res_init;
	pn_buffer_t uri_init;
	pn_buffer_t d11_init;
} pn_connection_t;

static int srv_sock;

pn_buffer_t *pn_buffer_new(pn_buffer_t *object) {
    //pn_buffer_t *object;
   
	if (NULL==object)
		object = malloc(sizeof(*object));
	
    if (object) {
        object->buff = object->init_buf;
        /*
        if (!object->buff) {
            free(object);
            return NULL;
        }
        */
        object->size = BUFFER_INIT_SIZE;
        object->free = BUFFER_INIT_SIZE;
    }
    return object;
}

void pn_buffer_free_buff(pn_buffer_t *buf) {
	 if (!buf)
        return;
    if (buf->buff != buf->init_buf && NULL!=buf->buff)
        free(buf->buff);
}

int pn_buffer_append_length(pn_buffer_t *buf, void *data, int length) {
    int lack, need = 0;
    char *temp;
   
    if (length >= buf->free) {
		//we need after bufer[length] -> 0
        lack = length - buf->free + 1;
        while (need < lack)
            need += BUFFER_INIT_SIZE;
        temp = malloc( buf->size + need );
        if (!temp)
            return -1;

		//memcpy(buf->buff, temp, buf->size);
		memcpy(temp, buf->buff, buf->size);
		pn_buffer_free_buff(buf);
		
        buf->buff = temp;
        buf->size += need;
        buf->free += need;
    }
    memcpy(buf->buff + buf->size - buf->free, data, length);
    buf->free -= length;
    buf->buff[buf->size - buf->free] = '\0';
    return 0;
}

int pn_buffer_append(pn_buffer_t *buf, void *data) {
    return pn_buffer_append_length(buf, data, strlen((char *)data));
}

int pn_buffer_find_string(pn_buffer_t *buf, char *str) {
    int idx = buf->size - buf->free;
    int slen = strlen(str);
    int i;
    for (i = 0; i < idx; i++) {
        if (idx - i >= slen) {
            if (!memcmp(buf->buff + i, str, slen)) return 1;
        } else {
            break;
        }
    }
    return 0;
}

int pn_buffer_length(pn_buffer_t *buf) {
    return buf->size - buf->free;
}

void pn_buffer_print(pn_buffer_t *buf) {
    fprintf(stderr, "%s", buf->buff);
}

void pn_buffer_clean(pn_buffer_t *buf) {
    buf->free = buf->size;
}

void pn_buffer_free(pn_buffer_t *buf) {
    if (!buf)
        return;
	pn_buffer_free_buff(buf);
    free(buf);
}

void pn_buffer_log(pn_buffer_t *buf) {
    if (!buf)
        return;
	printf("pn_buffe size %d free %d:%s\n", buf->size, buf->free, buf->buff);
}


int pn_header_finish(pn_buffer_t *request) {
	
    int end = request->size - request->free;

	const char *head_end;
	const char *content_lensz;
	int   content_len = 0;
	int	  head_len = 0;
	
	head_end =  strstr(request->buff, "\r\n\r\n");
	if (NULL==head_end)
		return 0;

	head_len = head_end - request->buff + 4;

	content_lensz = strstr(request->buff, "Content-Length:");
	if (NULL==content_lensz || content_lensz>head_end)
		return 1;

	//have content-length field
	content_lensz += sizeof("Content-Length:");
	content_len = atoi(content_lensz);

	print_log(RSSLOG_LV_TRACE, "buflen %d head len %d contentlen %d\n", end, head_len, content_len);
 
	if (content_len + head_len <= end )
		return 1;

    return 0;
}


const char* find_uri_byid(const char* obj_id , const struct obj_mem *objm, int nn_factor,int isNeedRef);

int IsNeedMapping(pn_connection_t *conn);

void pn_parse_header(pn_connection_t *conn) {
    char *eol;
    char method[16], uri[512], protocol[32];
   	char *host_field , tmp[32];
	
    eol = strchr(conn->request->buff, '\n');
    if (eol == NULL) {
        conn->stage = pn_closing_stage;
        return;
    }
   
    /*
    if (*(eol-1) == '\r')
        *(eol-1) = '\0';
    *eol = '\0';
    */
		
    sscanf(conn->request->buff, "%s %511s %s", method, uri, protocol);

	host_field = strstr(conn->request->buff, "Host:");
	if (host_field)
		sscanf(host_field, "%s %s", tmp, conn->host);
		
	print_log(RSSLOG_LV_INFO, "%d - method %s uri %s prot %s host %s size %d\n", conn->sock, method, uri, protocol, conn->host, pn_buffer_length(conn->request));
	
    if (!strcmp(method, "GET")) {
        conn->method = pn_method_get;
    } 
	else if (!strcmp(method, "POST")) {
        conn->method = pn_method_post;
	} else if (!strcmp(method, "HEAD")) {
        conn->method = pn_method_head;
    } else {
        conn->method = pn_method_unknow;
    }
    //pn_buffer_append(conn->uri, ".");
    pn_buffer_append(conn->uri, uri);
    if (pn_buffer_find_string(conn->uri, "..")) {
        print_log(RSSLOG_LV_ERROR, "[x] pn found connection header exists (..)\n");
        conn->stage = pn_closing_stage;
    }
}


atomic_t g_request_cnt = ATOMIC_INIT(0);

void connection_reading_header(pn_connection_t *conn) {
    char buff[1025];
    int nrecv;
   
    //nrecv = read_response(conn->sock, buff, 1024);
    print_log(RSSLOG_LV_TRACE, "pre read\n");
    nrecv = read_time(conn->sock, buff, 1024, 160);
    if (nrecv > 0) {
		print_log(RSSLOG_LV_TRACE, "read_time %d bytes\n", nrecv);
		buff[1024]=0;
        pn_buffer_append_length(conn->request, buff, nrecv);

		//printf("REQUEST: %s\n", conn->request->buff);
		
        if (pn_header_finish(conn->request)) {
            pn_parse_header(conn);
            conn->stage = pn_writing_header_stage;
        }
		else
			print_log(RSSLOG_LV_WARNING, "header not finished buf %d %s\n", nrecv, conn->request->buff);

    } else {
        print_log(RSSLOG_LV_ERROR , "cannot read data from connection ret %d, %s buf %s\n", nrecv, strerror(errno), conn->request->buff);
        //conn->stage = pn_closing_stage;
        conn->stage = pn_writing_header_stage;//IF the testclient error
    }
}
#define UDSI_PORT  8650
#define DSIWK_PORT 8080
#define REDIRECT_URI	"/mnt/disk1/300K/300kbps_00001.mp4?AuthInfo=&path=%2Fmnt%2Fdisk1%2F300K%2F300kbps_00001.mp4"


/* {{{ URL缂栫爜锛屾彁鍙栬嚜PHP 
   鐢ㄦ硶锛歴tring urlencode(string str_source)
   璇存槑锛氫粎涓嶇紪鐮?-_. 鍏朵綑鍏ㄩ儴缂栫爜锛岀┖鏍间細琚紪鐮佷负 +
   鏃堕棿锛?012-8-13 By Dewei
*/
const char* urlencode(const char* in_str, char* sz_encoded)
{
	
	int in_str_len = strlen(in_str);
	int out_str_len = 0;
	
	register unsigned char c;
	unsigned char *to, *start;
	unsigned char const *from, *end;
	unsigned char hexchars[] = "0123456789ABCDEF";

	from = (unsigned char *)in_str;
	end = (unsigned char *)in_str + in_str_len;
	to = start =  (unsigned char *)sz_encoded; //start = to = (unsigned char *) malloc(3*in_str_len+1);

	while (from < end) {
		c = *from++;

		if (c == ' ') {
			*to++ = '+';
		} else if ((c < '0' && c != '-' && c != '.') ||
			(c < 'A' && c > '9') ||
			(c > 'Z' && c < 'a' && c != '_') ||
			(c > 'z')) { 
				to[0] = '%';
				to[1] = hexchars[c >> 4];
				to[2] = hexchars[c & 15];
				to += 3;
		} else {
			*to++ = c;
		}
	}
	*to = 0;

	out_str_len = to - start;

	return NULL;
}


typedef struct{
	
	char	   mysql_host[64];
	int 	   mysql_db_port;
	char	   mysql_user[64];
	char	   mysql_pass[64];
	char	   mysql_db_name[64];

}DB_CONFIG;

typedef struct {

	 int 	    http_port;
	 int		nn_factor ;
	 //char		id_mask[128];
	 int		pull_port_num; //just for dsi or dsiproxy
	 int		dsi_pull_mod; // DSIWK = 1 ,use dsiwk to pull content , 
	 					      // 0 - use udsi ,
	 					      // 2 - use dsiproxy 
	 					      // 3 - use dsim to post reqeust and dsiproxy to get content
	 					      // 4 - dsim to post / get content
	 int		proxy_rate; // 0 :don't fake proxy / 1 : all proxy / 2 : 50%proxy / 3: 30%proxy 
	 char		dsi_host[64];
	 char		dsi_host_2[64];
	 volatile int   active_host_fail;
	 int		dsi_port;

	 char		upper_cdn_host[64];
	 int		upper_cdn_port;
	 int		thread_num;

	 int		stress_interval_ms; //stress test interval ,  if (stress_interval_ms==0)always mapping  else if ( terval > sress_interval_ms || !sprient ) don't mapping , 
	 
	 
 } CONFIG;

CONFIG g_config ;

DB_CONFIG g_db_cfg_local;
DB_CONFIG g_db_cfg_cache;


void connection_make_302_header(pn_connection_t *conn, const char* path, const char* url_prefix, int redirect_port )
{
	//char host[64];
	//char *port ;

		
	char location[1024];
	
	/*
	safe_strncpy(host, conn->host, sizeof(host));

	//printf("host %s\n", host);
	port = strchr( host , ':' );

	if (port)
		*port = '\0'; 
	*/
	//pn_buffer_log(conn->response);

	conn->status = pn_http_302;
	pn_buffer_append(conn->response, "HTTP/1.1 302 Found\r\n");
	//pn_buffer_append(conn->response, "Transfer-Encoding: chunked\r\n");

	//pn_buffer_log(conn->response);
	
	sprintf(location, "Location: http://%s:%d%s%s\r\n", g_config.dsi_host, redirect_port ,url_prefix, path);
	pn_buffer_append(conn->response, location);

	pn_buffer_append(conn->response,"Connection: close\r\n"); //connection_make_get_header() will add \r\n to str end

	//pn_buffer_append(conn->response, "\r\n\r\n0\r\n"); //for Transfer-Encoding: chunked
	
}



atomic_t port_dynamic = ATOMIC_INIT(0);

#define GET_DSI_HOST (g_config.active_host_fail?g_config.dsi_host_2:g_config.dsi_host)

void connection_make_201_header(pn_connection_t * conn, const char* url, const char* prefix, int direct_port)
{
	char temp[] = 	"<?xml version='1.0' encoding='UTF-8'?>\n"
					"<LocateCmdRes>\n"
  					"<TransferPort>%s:%d</TransferPort>\n"
  					"<AvailableRange>0-165128271</AvailableRange>\n"
  					"<TransferSessionID>%s%s</TransferSessionID>\n"
 					"<TransferTimeout>500</TransferTimeout>\n"
  					"<OpenForWrite>no</OpenForWrite>\n"
					"</LocateCmdRes>\n";
	char xml[1024] , conten_len[64];

/*	char host[64];
	safe_strncpy(host, conn->host, sizeof(host));

	//printf("host %s\n", host);
	char *port = strchr( host , ':' );

	if (port)
		*port = '\0'; 
	
*/	
	int xml_size = snprintf(xml, 1024,  temp, GET_DSI_HOST, direct_port , prefix, url);


	

	//pn_buffer_log(conn->response);
	conn->status = pn_http_201;
	
	sprintf(conten_len, "Content-Length: %d\r\n", xml_size);

	
	pn_buffer_append(conn->response, "HTTP/1.1 201 Created\r\n");
	pn_buffer_append(conn->response, conten_len);
	pn_buffer_append(conn->response, "Content-Type: text/xml\r\n\r\n");
	pn_buffer_append(conn->response, xml );
	//pn_buffer_log(conn->response);

}

inline int is_xml_char(char a)
{
	if ('<'==a || '>'==a )
		return 1;

	return 0;
}


int get_xml_field(const char* xml_buf, const char* field, char* outbuf, int outbuf_len)
{
	const char* start = strstr(xml_buf, field); //example field="<TransferSessionID>"

	if (NULL==start)
	{
		print_log(RSSLOG_LV_WARNING, "get field %s fail %s\n", field, xml_buf);
		return -1;
	}

	start += strlen(field);
	const char* end = start;

	for ( ; *end!=0 ; end++)
		if (is_xml_char(*end))
			break;

	if (*end==0)
	{
		print_log(RSSLOG_LV_WARNING, "get end of field %s fail %s\n", field, xml_buf);
		return -2;
	}
	int len = end - start;

	if (len + 1 > outbuf_len)
	{
		print_log(RSSLOG_LV_WARNING, "overflow %d field %s \n", len, field);
		return -2;
	}

	memcpy(outbuf, start, len);
	outbuf[len]=0;

	return 0;

	
}

#define FOR_CTC
int 	get_id_field(const char* obj_id)
{
	int   field_id = 0;

#ifdef FOR_CTC
	int len = strlen(obj_id)-1;
	if (len>31) len =31;
	field_id = obj_id[len] - '0';
	if (field_id<0 || field_id>9)
	{
		printf("ERR: get_id_field() field_id %d invalid\n", field_id );
		return 0;
	} 
#else
	char  int_id[5] ;
	
	memcpy(int_id , obj_id+18, 4);
	int_id[4] = 0;

	field_id = atoi(int_id);

#endif
	return field_id;
}


int _str_end_replace(char* source, int len , const  char *rep, const char *with)
{
	char* tmp = strstr(source, rep);
	if (NULL==tmp)
		return -1;

	if (source + len <= tmp + strlen(with))
		return -2; //buffer overflow

	strcpy(tmp, with);
	return 0;
}

const char* url_prefix[10]=
{
"",
"/mp3m", // 1 - mp4 3m
"",
"", 	  // 3 - hls is default bitrate 4M
"/ts75",  // 4 - IPTV 7.5M
"/ts23",  // 5 - IPTV 2.3M
"/ts16",  // 6 - IPTV 1.6M
"",
"",
""
};


void connection_make_post_header(pn_connection_t * conn)
{
	char url_id[64] ; 
	char type_d11[16] ;
	char provider[16];
	
	//char *uni_id_end;
	//char  default_tran_id[64] = "<TransferContentID>00000000000000000021010000000001\n";
	int ret ;

	
	if (pn_method_post!=conn->method)
	{
		print_log(RSSLOG_LV_ERROR,"INVAID method %d request %s\n", conn->method, conn->request->buff);
		
		//return;
	}

	ret = get_xml_field(conn->request->buff, "<TransferContentID>" , url_id, sizeof(url_id));
	if (ret<0)
	{
		print_log(RSSLOG_LV_ERROR,"can't find TransferContentID, request %s\n", conn->request->buff );
		return;
	}

	ret = get_xml_field(conn->request->buff, "<SubType>" , type_d11, sizeof(type_d11));
	if (ret<0)
	{
		print_log(RSSLOG_LV_ERROR,"can't find SubType, request %s\n", conn->request->buff );
		return;
	}
	
	ret = get_xml_field(conn->request->buff, "<TransferProviderID>" , provider, sizeof(provider));
	if (ret<0)
	{
		print_log(RSSLOG_LV_ERROR,"can't find TransferProviderID, request %s\n", conn->request->buff );

		return;
	}

	printf("TransferContentID %s SubType %s TransferProviderID %s\n", url_id, type_d11, provider);
	
	//int64_t id_int = atoll(url_id);
	const char* path = NULL;

	
	int isNeedRef = IsNeedMapping(conn);

	int uid_field = get_id_field(url_id);
	const char* uid_prefix = url_prefix[uid_field];

	if (g_config.proxy_rate==0)
		path = find_uri_byid(url_id, &g_local, g_config.nn_factor, isNeedRef);
	else if (g_config.proxy_rate==1)
		path = NULL;
	else if (0 == atomic_read(&g_request_cnt) % g_config.proxy_rate)
		path = NULL;
	else
		path = find_uri_byid(url_id, &g_local, g_config.nn_factor, isNeedRef);

	atomic_inc(&g_request_cnt);
	
	char url_path[1024] ;
	

	int port = g_config.dsi_port ; //dsiw port
	if (path==NULL)
	{
		//LOCAL AREA LOST , NEED PULL
		if (0==g_config.dsi_pull_mod)//use DSI pull via D1.1
		{
			// we always use dsi to pull content
			//TMD!!!! the cache layer DSI can't use this function to pull content
			sprintf(url_path , 
				"/vod/%s/%s?AuthInfo=&path=%%2FSMG%%2Fvod%%2Ftest%%2F0000000000000000000000_0000.flv" , 
				provider, url_id);
	

			port = 17770 + atomic_read(&port_dynamic)%g_config.pull_port_num ;
			atomic_inc(&port_dynamic);
					
			connection_make_201_header(conn, url_path, uid_prefix, port);
			print_log( RSSLOG_LV_INFO, "UDSIPULL201 port %d %s%s\n", port, uid_prefix, url_path);
			
		}
		else // D1.1 use dsiwk or dsiproxy pull via normal GET
		{
			char url_path2[1024];
			
			path = find_uri_byid(url_id, &g_cache, g_config.nn_factor, isNeedRef);
			TRACE("cache_path %s\n", path );
			if ( NULL==path || 0!= strncmp(path, "/vod/", 5) )
			{
				conn->status = pn_http_notfound; //need pull
				pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found(not found /vod/\r\n");
				print_log(RSSLOG_LV_ERROR, "ERR Cache 404 id %s\n", url_id);
			}
			else
			{
				//etc . /vod//home/SMG/1M/mp4test2_1M_00001.mp4
				path += sizeof("/vod/") -2 ;
				if (path[1]=='/')
					path++;
				
				strcpy(url_path, path);

				if (0==strcmp("INDEX", type_d11))
				{
					ret = _str_end_replace(url_path, sizeof(url_path2), ".", ".index" );
					if (ret<0)
						print_log(RSSLOG_LV_ERROR, "INDEX url fail %s\n", url_path);
				}
				if (1==g_config.dsi_pull_mod)
				{
					//use dsiwk to pull
					sprintf(url_path2, "/cache%s", url_path);
					connection_make_201_header(conn, url_path2, uid_prefix,  g_config.dsi_port );
					print_log(RSSLOG_LV_INFO, "WKPULL201 %s%s\n", uid_prefix, url_path2);
				}
				else 
				{
					//use dsiporxy to pull
					port = 8081 + atomic_read(&port_dynamic)%g_config.pull_port_num ;
					atomic_inc(&port_dynamic);
					
					connection_make_201_header(conn, url_path, uid_prefix,  port);
					print_log(RSSLOG_LV_INFO, "PROXYPULL201 port %d %s%s\n", port, uid_prefix,  url_path);						
				}
			}


		}
	}
	else
	{
		//id in local 锛?path is like /vod//mnt/disk1 ....
		if (0!= strncmp(path, "/vod/", 5))
		{
			conn->status = pn_http_notfound; //need pull
			pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found(not found /vod/\r\n");
			print_log(RSSLOG_LV_ERROR, "ERRB 404 id %s\n", url_id);
		}
		else
		{
			// LOCAL GET 201
			path += sizeof("/vod/") -2 ;
			if (path[1]=='/')
				path++;

			strcpy(url_path, path);

			if (0==strcmp("INDEX", type_d11))
			{
				ret = _str_end_replace(url_path, sizeof(url_path), ".", ".index" );
				if (ret<0)
					print_log(RSSLOG_LV_ERROR, "INDEX url fail %s\n", url_path);
			}
			connection_make_201_header(conn, url_path,uid_prefix,  g_config.dsi_port );
			print_log(RSSLOG_LV_INFO, "LOCAL201 (%s) %d %s/%s\n", GET_DSI_HOST, uid_field, uid_prefix, url_path);
		}
	}
}

unsigned int JSHash(const char *str)
{
    unsigned int hash = 1315423911;
 
    while (*str)
    {
        hash ^= ((hash << 5) + (*str++) + (hash >> 2));
    }
 
    return (hash & 0x7FFFFFFF);
}

#define  _atouid   JSHash

int send_d11_request(const char* host, int port, const char* provider , const char* uni_content, const char* D11_type, char* transid_buf, char* get_host, int* get_port);

long long time_difference(struct timeval *t1, struct timeval *t2);


static pthread_mutex_t antiCaptureLock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;


//client is not spirent : ret 0 , don't mapping
//spirent client , if in stress test (interval < 1200 ms) ,  ret 1 , mapping 
//spirent client , if long time no see (>1200 ms), ret 0  don't mapping
int IsNeedMapping(pn_connection_t *conn)
{
	if (g_config.stress_interval_ms<=0)
		return 1; //always mapping
	
	int spirent = (NULL==strstr(conn->request->buff, "User-Agent"))?1:0; //不带agent 认为是思博伦

	if(0==spirent)
	{
		//client have agent , if agent is not spirent , it is not spirent
		if (NULL==strstr(conn->request->buff, "spirent"))
		{
			//printf("request not spirent----%s\n", conn->request->buff );
			return 0;
		}
	}

	int ret = 1;
	
    struct timeval t_currentTime;
	static struct timeval t_lastTime;


	gettimeofday(&t_currentTime, (struct timezone *)0);
	
	pthread_mutex_lock(&antiCaptureLock);
   
	
	if(time_difference(&t_currentTime,&t_lastTime)>g_config.stress_interval_ms*1000)
		ret = 0;
	
	memcpy(&t_lastTime,&t_currentTime,sizeof(struct timeval));

	pthread_mutex_unlock(&antiCaptureLock);
	
	return ret;
}

void connection_make_get_header(pn_connection_t *conn) {
        struct stat stat_buf;

	char uri[1024];
	char provider[16] = {0};
	
	const char* url_start ;
    const char* url_id_start;
	char 		url_id[1024] ;
	const char* path = NULL;
    int64_t id_int ;
    int 	uid_field;
	const char* uid_prefix = NULL;
	
	int isNeedRef = IsNeedMapping(conn);
	
	safe_strncpy( uri, conn->uri->buff, 1024);
	
	if ( NULL!=(url_start = strstr(uri, "/ut")) || NULL!=(url_start = strstr(uri, "/huawei")) ||  NULL!=(url_start = strstr(uri, "/cisco")))
	{
		//url_start += sizeof("/ut") - 1 ; 
		url_start++;
		
        url_id_start = strstr(url_start, "/");

        if (NULL!=url_id_start)
        {
        	int len = url_id_start - url_start ;
			if (len>0 && len < sizeof(provider)-1)
				strncpy(provider, url_start, len );
			
            url_id_start++; //pass "/"
        }    
        else
        {
            url_id_start = url_start;
        }    

		safe_strncpy(url_id, url_id_start, sizeof(url_id));

		const char *tmp = strstr(	url_id_start , "?" );
		if (NULL!=tmp)
			url_id[tmp-url_id_start] = 0;
			
		
		uid_field = get_id_field(url_id);
		uid_prefix = url_prefix[uid_field];

		id_int = _atouid(url_id);
		if (g_config.proxy_rate==-1)
			path = uri;
		else if (g_config.proxy_rate==0)
			path = find_uri_byid(url_id, &g_local, g_config.nn_factor,isNeedRef);
		else if (g_config.proxy_rate==1)
			path = NULL;
		else if (0 == id_int % g_config.proxy_rate)
			path = NULL;
		else
			path = find_uri_byid(url_id, &g_local, g_config.nn_factor,isNeedRef);

		//atomic_inc(&g_request_cnt);
		int port = 0;
		if (path==NULL)
		{
			int pull_mode = g_config.dsi_pull_mod;
			
			//need pull
			if (0==pull_mode || 0==isNeedRef)//use uDSI pull via D1.1
			{
				char url_path[1024] ;

				
				sprintf(url_path , 
					"/vod/%s/%s?AuthInfo=&path=%%2FSMG%%2Fvod%%2Ftest%%2F0000000000000000000000_0000.flv" , 
					provider, url_id);

				port = UDSI_PORT + atomic_read(&port_dynamic)%g_config.pull_port_num ;
				atomic_inc(&port_dynamic);

				connection_make_302_header(conn, url_path, "", port );
				
				print_log( RSSLOG_LV_INFO, "DSIPULL302 port %d %s\n", port, url_path);
			}
			else if (3==pull_mode)
			{

				char transid_buf[2048] ;
				//use D1.1 pull from upper layer CDN
				send_d11_request(g_config.upper_cdn_host, g_config.upper_cdn_port, provider, url_id, "BASE", transid_buf, NULL ,NULL);

				//use dsiproxy to pull
				port = 8081 + atomic_read(&port_dynamic)%g_config.pull_port_num;
				atomic_inc(&port_dynamic);
				
				connection_make_302_header(conn, transid_buf, "/" ,port);
				
				print_log(RSSLOG_LV_INFO, "D11PULL302 port %d %s\n", port, transid_buf); 					


			}
			else if (4==pull_mode)
			{
				char transid_buf[2048] ;
				char get_ip[64];
				int  get_port ;
				
				//use D1.1 pull from upper layer CDN and proxy it for client
				send_d11_request(g_config.upper_cdn_host, g_config.upper_cdn_port, provider, url_id, "BASE", 
				transid_buf, get_ip , &get_port);

				
				http_proxy_content(get_ip, get_port, transid_buf, 0 , conn->sock);

				conn->stage = pn_closing_stage;

			}
			else // use dsiwk or dsiproxy pull via normal GET
			{
				char url_path2[1024];
				
				path = find_uri_byid(url_id, &g_cache,  g_config.nn_factor,isNeedRef);
				
				TRACE("cache_path %s\n", path );
				if ( NULL==path || 0!= strncmp(path, "/vod/", 5) )
				{
					conn->status = pn_http_notfound; //need pull
					pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found(not found /vod/\r\n");
					print_log(RSSLOG_LV_ERROR, "ERR Cache 404 id %s\n", url_id);
				}
				else
				{
					//etc . /vod//home/SMG/1M/mp4test2_1M_00001.mp4
					path += sizeof("/vod/") -2 ;
					if (path[1]=='/')
						path++;

					
					if (1==pull_mode)
					{
						//use dsiwk to pull
						sprintf(url_path2, "/cache%s", path);
						connection_make_302_header(conn, url_path2, uid_prefix , g_config.dsi_port);
						print_log(RSSLOG_LV_INFO, "WKPULL302 %s\n", url_path2);
					}
					else 
					{
						//use dsiproxy to pull
						port = 8081 + atomic_read(&port_dynamic)%g_config.pull_port_num;
						atomic_inc(&port_dynamic);

						if (port==8081 && rand()%5 == 0)
						{
							//port 8081 is bind to cpu0 , which has timer interupt
							port = 8082;
							atomic_inc(&port_dynamic);
						}
						
						connection_make_302_header(conn, path, uid_prefix ,port);
						
						print_log(RSSLOG_LV_INFO, "PROXYPULL302 port %d %s\n", port, path);						
					}
				}

				
				

			}
			
		}
		else
		{
			if (g_config.proxy_rate==-1)
			{
				if ('.' == *path) path++; //pass "."
				
				connection_make_302_header(conn, path ,"", g_config.dsi_port ); //to dsim SLB
				print_log(RSSLOG_LV_INFO, "RR302 %s\n", path  ); 
			}
			//id in local 锛?path is like /vod//mnt/disk1 ....
			else if (0!= strncmp(path, "/vod/", 5))
			{
				conn->status = pn_http_notfound; //need pull
				pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found(not found /vod/\r\n");
				print_log(RSSLOG_LV_ERROR, "ERRB 404 id %s\n", url_id);
			}
			else
			{
				path += sizeof("/vod/") -2 ;
				if (path[1]=='/')
					path++;
				connection_make_302_header(conn, path, uid_prefix,  g_config.dsi_port);
				print_log(RSSLOG_LV_INFO, "LOCAL302 %s\n", path);
			}
		}		
	
	}
	else if(!strcmp(conn->uri->buff,"/hostdown"))
	{
		g_config.active_host_fail=1;
		print_log(RSSLOG_LV_INFO, "hostdown ----------------- Switch to HOST_2. IP:%s\n", GET_DSI_HOST );
		conn->status = pn_http_200;
		pn_buffer_append(conn->response, "HTTP/1.0 200 OK\r\n");
	}
	else if(!strcmp(conn->uri->buff,"/hostup"))
	{		
		g_config.active_host_fail=0;
		print_log(RSSLOG_LV_INFO, "hostup ----------------- Switch to HOST_1. IP:%s\n", GET_DSI_HOST );
		conn->status = pn_http_200;
		pn_buffer_append(conn->response, "HTTP/1.0 200 OK\r\n");
	}
	//normal web server to send local file to client
    else if (stat(conn->uri->buff, &stat_buf) == -1) {
        conn->status = pn_http_notfound;
        pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found\r\n");
		print_log(RSSLOG_LV_ERROR, "404 open fail %s\n", conn->uri->buff);
    } else {
        if (S_ISDIR(stat_buf.st_mode)) {
            pn_buffer_append(conn->uri, "index.html");
            if (stat(conn->uri->buff, &stat_buf) == -1) {
                conn->status = pn_http_notfound;
                pn_buffer_append(conn->response, "HTTP/1.0 404 Not Found\r\n");
            } else {
				//ning OPEN DIR
				
				char content_length[256];
                
                conn->handle_fd = open(conn->uri->buff, O_RDONLY);
                if (conn->handle_fd < 0 ) {
                    pn_buffer_append(conn->response, "HTTP/1.0 500 Internal Server Error\r\n");
                } else {
                    pn_buffer_append(conn->response, "HTTP/1.0 200 OK\r\n");
                    sprintf(content_length, "Content-Length: %lu\r\n", stat_buf.st_size);
                    pn_buffer_append(conn->response, content_length);
                }
            }
        } else if (S_ISREG(stat_buf.st_mode)) {
            char content_length[256];
           
            conn->handle_fd = open(conn->uri->buff, O_RDONLY | O_NOATIME | O_LARGEFILE | O_NONBLOCK );
            if (conn->handle_fd < 0 ) {
                pn_buffer_append(conn->response, "HTTP/1.0 500 Internal Server Error\r\n");
            } else {
                pn_buffer_append(conn->response, "HTTP/1.1 200 OK\r\n");
                sprintf(content_length, "Content-Length: %lu\r\n", stat_buf.st_size);
                //pn_buffer_append(conn->response, content_length);
				pn_buffer_append(conn->response, "Transfer-Encoding: chunked\r\n" );
            }
        } else {
            pn_buffer_append(conn->response, "HTTP/1.0 500 Internal Server Error\r\n");
        }
    }
    pn_buffer_append(conn->response, "\r\n");
    //pn_buffer_print(conn->response);
}

void connection_send_header(pn_connection_t *conn) {
    int bytes = pn_buffer_length(conn->response);
    int nsend, i = 0;

	if (conn->stage!=pn_writing_header_stage)
		return;
	
    print_log(RSSLOG_LV_TRACE, "send response header %d : %s\n", bytes, conn->response->buff );
	
    while (i < bytes) {
        nsend = write(conn->sock, conn->response->buff + i, bytes - i);
        if (nsend > 0) {
            i += nsend;
        } else {
            sleep(1);
            continue;
        }
    }
    conn->stage = pn_writing_body_stage;
}



 
const int g_bitrate_bps = 800*1024; //  3Mbps

#define READ_SIZE 256*1024
#define SEND_SIZE 4*1024*1024

//not use anymore
void connection_sendfile_body(pn_connection_t *conn)
{
   	int bufsize = SEND_SIZE;

	
    struct timeval tv_start;


	
    if (conn->handle_fd<0) {
        conn->stage = pn_closing_stage;
        return;
    }

	if (conn->status!=pn_http_ok)
	{
		conn->stage = pn_closing_stage;
		return;
	}

	setsockopt(conn->sock, SOL_SOCKET, SO_SNDBUF, (void*)&bufsize, sizeof(bufsize));

	int flag_sock = fcntl(conn->sock, F_GETFL, 0);
	fcntl(conn->sock, F_SETFL, flag_sock|O_NONBLOCK);

	gettimeofday(&tv_start, (struct timezone *)0);
	
	pthread_mutex_lock(&cb_lock);

	int index = en_queue(&todo_cb);

	if (index>=0)
	{
			todo[index].sock = conn->sock;
			todo[index].file_fd = conn->handle_fd;
			todo[index].read_pos =0;
			todo[index].start_tv = tv_start;
	}
	else
	{
		print_log(RSSLOG_LV_ERROR, "sock %d insert fail!!! queue head %d tail %d\n", 
			conn->sock, todo_cb.head, todo_cb.tail );
	}
	pthread_mutex_unlock(&cb_lock);

	conn->stage = pn_writing_body_stage_thread;
	/*
	struct timeval tv_now;
	struct timeval tv_last;
	
	long long need_us = 0;
	off_t total_readed=0;
	
	int bytes;
	
      for(;;) {
		bytes = sendfile( conn->sock, conn->handle_fd, &total_readed, READ_SIZE );
		if (bytes<0)
		{
			print_log(RSSLOG_LV_ERROR,"sendfile fd %d ret %d error:%s\n", conn->handle_fd, bytes, strerror(errno));
			break;
		}
		else if (bytes==0) //EOF
		{
			print_log(RSSLOG_LV_INFO, "sendfile fd %d ret %d EOF\n", conn->handle_fd, bytes );
			break;
		}		
		//total_readed+=bytes;

		print_log(RSSLOG_LV_INFO,"PPPP file %d sock %d bytes %d readed %lld\n", conn->handle_fd,  conn->sock, bytes, total_readed );
		
		gettimeofday(&tv_now, (struct timezone *)0);
		long long diff_us = time_difference(&tv_now,&tv_start);
	
		need_us = 1000LL*1000LL*total_readed*8LL/g_bitrate_bps;
	
		long long diff = need_us - diff_us;
		if (diff>10000)
			usleep(diff);
		else
			usleep(10000);
		
	}
	
	close(conn->handle_fd);
	conn->stage = pn_closing_stage;
	*/

}
//not use anymore
void* sendfile_thread(void* arg)
{
	
	static http_req_cb stream_cb[MAX_STREAM_PERTHREAD] = {{0}};
	init_queue( &todo_cb , 1024);

	int i;

	long long need_us , diff_us;

	struct timeval tv_now;

	

		

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGALRM);
	struct timespec time_spec;
	
	for(;;)
	{
		int index = 0;


		//retrive new http send body request
		pthread_mutex_lock(&cb_lock);
		while ((index = de_queue(&todo_cb))>=0)
		{
			for (i=0 ;i < MAX_STREAM_PERTHREAD ; i++)
			{
				if (stream_cb[i].sock <=0 )
				{
					//find a free slot to fill
					stream_cb[i] = todo[index];
					break;
				}
			}
		}
		pthread_mutex_unlock(&cb_lock);

		//timer
		time_spec.tv_sec = 0;
		time_spec.tv_nsec = 2000*1000; //nanosecond , 2ms
		while (1)
		{
			i = pselect(0, NULL, NULL, NULL, &time_spec, &sigmask);

			if (!((i == -1) && (errno == EINTR)))
				break;
			//rss_log_with_location(RSSLOG_FL_COMMON,RSSLOG_LV_INFO, "in cmd_read_timed_2, i=%d, errno=%d, %s\n", i, errno, strerror(errno));
		}

		print_log(RSSLOG_LV_INFO, "tick A...\n");
		
		gettimeofday(&tv_now, (struct timezone *)0);
		
		//loop for the sendfile item
		for (i=0 ;i < MAX_STREAM_PERTHREAD ; i++)
		{
			http_req_cb* scb = &stream_cb[i];
			if (scb->sock<=0)
				continue;
				
			diff_us = time_difference(&tv_now,&(scb->start_tv));
			need_us = 1000LL*1000LL*scb->read_pos*8LL/g_bitrate_bps;

			if (diff_us<need_us)
				continue;

			
			int bytes = sendfile( scb->sock, scb->file_fd, &scb->read_pos, READ_SIZE );
			if (bytes<0)
			{
				print_log(RSSLOG_LV_ERROR,"sendfile fd %d ret %d error:%s\n", scb->file_fd, bytes, strerror(errno));
				close(scb->file_fd);
				close(scb->sock);
				scb->sock = -1;
				continue;
			}
			else if (bytes==0) //EOF
			{
				print_log(RSSLOG_LV_INFO, "sendfile fd %d ret %d end %lld EOF\n", scb->file_fd, bytes , scb->read_pos);
				close(scb->file_fd);
				close(scb->sock);
				scb->sock = -1;
				continue;;
			}	
			
			print_log(RSSLOG_LV_INFO,"SENDFILE file %d sock %d bytes %d readed %lld\n", scb->file_fd,  scb->sock, bytes, scb->read_pos);
		}
		
		
	}
}



//鍙戦€佹枃浠?
void connection_send_body(pn_connection_t *conn)
{
    char buff[READ_SIZE+3];
    int bytes;
   	int bufsize = SEND_SIZE; //only for set socket send buffer

	
    if (conn->handle_fd<0) {
        conn->stage = pn_closing_stage;
        return;
    }

	if (conn->status!=pn_http_ok)
	{
		conn->stage = pn_closing_stage;
		return;
	}
	
    struct timeval tv_start;
	struct timeval tv_now;
	struct timeval tv_last;
	
	setsockopt(conn->sock, SOL_SOCKET, SO_SNDBUF, (void*)&bufsize, sizeof(bufsize));
	
	gettimeofday(&tv_start, (struct timezone *)0);
	tv_last = tv_now;
	
	long long need_us = 0, total_readed=0;
    for(;;) {

		print_log(RSSLOG_LV_INFO,"PPPP file %d sock %lld scheduled %d\n", conn->handle_fd ,  conn->sock, total_readed );
        bytes = read(conn->handle_fd , buff, READ_SIZE);
		
		if (bytes < 0 )
		{	
			print_log(RSSLOG_LV_ERROR,"read fd %d error:%s\n", conn->handle_fd, strerror(errno));
			stable_send(conn->sock, "0\r\n\r\n" , 5 , NULL );//the lastest chunk 
			break;
			//error
		}
		else if (bytes==0)
		{
			print_log(RSSLOG_LV_INFO,"read fd %d EOF\n", conn->handle_fd);
			
			stable_send(conn->sock, "0\r\n\r\n" , 5 , NULL );//the lastest chunk 
			break;		
		}

		char chunk_buf[64];
		sprintf(chunk_buf, "%x\r\n", bytes);
		printf("%s\n", chunk_buf);
		
		
		
		int ret = stable_send(conn->sock, chunk_buf, strlen(chunk_buf), NULL);
		if (ret<=0)
		{
			print_log( RSSLOG_LV_INFO, "stable_send err1 %d\n", ret );
			break;
		}
		total_readed+=bytes;
       	print_log(RSSLOG_LV_INFO,"PPPP file %d sock %lld readed %d\n", conn->handle_fd ,  conn->sock, total_readed );
		
		//add chunk end
		buff[bytes] = '\r' ;
		buff[bytes+1] = '\n';
		
        ret = stable_send( conn->sock, buff, bytes + 2, NULL);
		if (ret<=0)
		{
			print_log( RSSLOG_LV_INFO, "stable_send err2 %d\n", ret );
			break;
		}
			
		print_log(RSSLOG_LV_INFO,"PPPP file %d sock %lld sended %d\n", conn->handle_fd ,  conn->sock, total_readed );
        

		ret = posix_fadvise(conn->handle_fd, total_readed , READ_SIZE, POSIX_FADV_WILLNEED);
		if (ret!=0)
			print_log(RSSLOG_LV_ERROR,"posix_fadvise fd %d err %s\n", conn->handle_fd, strerror(errno));
		
		gettimeofday(&tv_now, (struct timezone *)0);
		long long diff_us = time_difference(&tv_now,&tv_start);

		need_us = 1000LL*1000LL*total_readed*8LL/g_bitrate_bps;
		
		long long diff = need_us - diff_us;
		
		print_log( RSSLOG_LV_INFO, "-----readed %lld diff %lld need_ms %lld diff_ms %lld\n", total_readed, diff, need_us/1000, diff_us/1000 );
		
		if (diff>1000000)
			diff = 1000000;
		
		if (diff>10000)
			usleep(diff);
		else if(diff >0 )
			usleep(10000);
		
		print_log( RSSLOG_LV_INFO, "sleep diff_ms %lld\n", diff/1000);
    }
    close(conn->handle_fd);
    conn->stage = pn_closing_stage;
}

static int conn_srv( const char* srv_ip , int srv_port )
{
	int sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = inet_addr(srv_ip);
	addr.sin_port = htons( srv_port );
	addr.sin_family = AF_INET;
	
	int ret = connect( sockfd , (struct sockaddr*)&addr , sizeof( addr ) ); 
	if (ret == -1) {
		printf("error connect %s:%d fail %s\n", srv_ip ,  srv_port, strerror(errno));
		close(sockfd);
		return -1;
	}
	return sockfd;
}



const	int TransferRate[11] =
{
			0,
			3*1024*1024, //end of 1 -- 3M mp4
			0,0,
			7.5*1024*1024,//end of 4 -- 7.5M
			2.3*1024*1024,//end of 5 -- 2.3M
			1.6*1024*1024,//end of 6 -- 1.6M
			0,0,0,0
};


int send_d11_request(const char* host, int port, const char* provider , const char* uni_content, const char* D11_type,
						char* trans_id_buf , char* get_ip, int* get_port)
{
	int range = 0;

	/*char temp[] = "<?xml version='1.0' encoding='UTF-8'?>"
				"<LocateCmdReq>"
				"<TransferContentID>%s</TransferContentID>"
				"<TransferProviderID>%s</TransferProviderID>"
				"<SubType>%s</SubType>"
				"<TransferRate>2000000</TransferRate>"
				"<IngressCapacity>20000000</IngressCapacity>"
				"<TransferDelay>0</TransferDelay>"
				"<Range>%d-</Range>"
				"</LocateCmdReq>";
	*/
	char tmp_index[] = "<?xml version='1.0' encoding='UTF-8' ?>" 
					"<LocateCmdReq>"
					"<TransferProviderID>%s</TransferProviderID>"
					"<OriginContentID>%s</OriginContentID>"
					"<TransferContentID>%s</TransferContentID>"
					"<SubType>INDEX</SubType>"
					"<TransferRate>0</TransferRate>"
					"<IngressCapacity>100000000</IngressCapacity>"
					"<TransferDelay>0</TransferDelay>"
					"<Range>0-</Range>"
					"</LocateCmdReq>";

	char tmp_base[] ="<?xml version='1.0' encoding='UTF-8' ?>"
					"<LocateCmdReq>"
					"<TransferProviderID>%s</TransferProviderID>"
					"<OriginContentID>%s</OriginContentID>"
					"<TransferContentID>%s</TransferContentID>"
					"<SubType>BASE</SubType> "
					"<TransferRate>%d</TransferRate>"
					"<IngressCapacity>%d</IngressCapacity>"
					"<TransferDelay>0</TransferDelay>"
					"<Range>%d-</Range>"
					"</LocateCmdReq>";

	/*
     char tmp_uri[] = "<\?xml version=\"1.0\" encoding=\"UTF-8\" \?>\r\n"
   			"<LocateCmdReq>\r\n"
   			"<TransferProviderID>%s</TransferProviderID>\r\n"
   			"<OriginContentID>%s</OriginContentID>\r\n"
   			"<TransferContentID>%s</TransferContentID>\r\n"
   			 "<SubType>URI</SubType> \r\n"
   			 "<TransferRate>%d</TransferRate>\r\n"
   			 "<IngressCapacity>%d</IngressCapacity>\r\n"
   			 "<TransferDelay>-2000</TransferDelay>\r\n"
   			 "<Range>%d-</Range>\r\n"
   			 "</LocateCmdReq>\r\n";
	*/

	char post_header[] = "POST /ContentTrans HTTP/1.1\r\n"
						"Host: %s:%d\r\n"
						"Content-Type: text/xml\r\n"
						"Content-Length: %d\r\n\r\n";
	
	char host_ip[64];
	int  host_port = port;
	char resp_buf[4096];
	int ret ;
	int sock;

	strcpy(host_ip, host);

	for (; ; )
	{
		sock = conn_srv( host_ip , host_port );

		if (sock<0)
		{
			print_log( RSSLOG_LV_ERROR, "D11 connect %s fail\n", host);
			return -3;
		}

		char body[1024] , header[1024+128]; 
		
		int body_size = 0;
		int TransferRate_real = 0;

		if (0!=strcmp(D11_type, "INDEX"))
		{
			int filed = get_id_field(uni_content);
			TransferRate_real = TransferRate[filed];
			//int rang_index = rand()%ALL_RANGE_TYPE ; 
			//range = play_range[rang_index];
			print_log(RSSLOG_LV_TRACE, "***********************TYPE : TransferRate_real %d , range %d********************\n", TransferRate_real, range );
			range *= TransferRate_real/8;
		}

		

		if (0==strcmp(D11_type, "INDEX"))
		{
			body_size = snprintf(body, sizeof(body), tmp_index, provider,uni_content, uni_content);
		}
		else if (0==strcmp(D11_type, "BASE"))
		{			
			//TransferRate_real = 0; //just for test

			body_size = snprintf(body, sizeof(body), tmp_base, provider, uni_content, uni_content, TransferRate_real ,TransferRate_real ,range );

		}
		/*else if (0==strcmp(D11_type, "URI"))
		{
			char uri[64] ;
			strcpy(uri, uni_content);
			strcat(uri, uri_end[uri_end_index]);
			
			range *= size_rate[uri_end_index];
			TransferRate_real *= size_rate[uri_end_index]*1.02 ;
			body_size = snprintf(body, sizeof(body), tmp_uri, provider, uni_content, uri  ,TransferRate_real,TransferRate_real,range);
		}*/
		else
		{
			print_log(RSSLOG_LV_ERROR, "SEND D11 REQ err INVALID TYPE %s\n",D11_type );
			return -1;
		}

		
		/*int header_size = */snprintf(header, sizeof(header), post_header, host_ip, host_port, body_size );

		strcat(header, body);

		print_log(RSSLOG_LV_INFO, "----------------------SEND D11 POST REQ: %s------------------------------\n %s\n", D11_type, header);
		writen(sock, header, strlen(header));



		int byte_sum = 0;
		char* p = (char*)resp_buf;

		while( (ret = read_time( sock , p , sizeof(resp_buf) , 2000 ))>0) //200ms  timeout
		{
			if( ret <= 0 )
			{
				//PTRACE("read_time ret %d\n", ret);
				return ret;
			}
			p+=ret;
			byte_sum+=ret;


			if( byte_sum >= sizeof(resp_buf) )
				break;

			if (NULL!=strstr((const char*)resp_buf, "\r\n\r\n"))
			{
				//PTRACE("--read response end flag\n");
				break;
			}
		}

		printf("POST response: %s\n", resp_buf);

		if (strstr(resp_buf, "302 Found" ))
		{
			printf("-->need 302 redirect\n");

			char* location = strstr( resp_buf, "Location: http://" );
			if (location)
			{
				char host2[64];
				strncpy(host2, location+strlen("Location: http://"), 30);
				host2[63]=0;
				char *p = strstr(host2, "/");
				if (p)
				{
					*p = 0;
					char *p2 = strstr(host2, ":");
					if (p2)
					{
						host_port = atoi(p2+1);
						*p2 = 0;
						strcpy( host_ip, host2);

						print_log(RSSLOG_LV_INFO, "302 HOST %s port %d\n", host_ip, host_port);
						close(sock);
						continue;
					}
				}
				else
					print_log(RSSLOG_LV_ERROR, "HOST %s not found end\n", host2);
			}
			else
				print_log(RSSLOG_LV_ERROR, "not found location\n");
		}
		break;
	}
	
	char trans_id[1024];
	

	if ( get_ip!=NULL  && get_port!=NULL)
	{

		char trans_addr[64];
		ret = get_xml_field( resp_buf, "<TransferPort>", trans_addr, sizeof(trans_addr));

		if (ret<0)
			return -4; 
		
		char *ptmp = strstr(trans_addr, ":");

	    if(ptmp)
	    {
	    	*ptmp = 0;
	    	ptmp++;
	    	*get_port = atoi(ptmp);
	    }
		else
			*get_port = 80;

		strcpy(get_ip, trans_addr);
	}


	print_log(RSSLOG_LV_INFO, "D11 <TransferPort> %s : %d\n", get_ip , get_port );

	ret = get_xml_field( resp_buf, "<TransferSessionID>", trans_id, sizeof(trans_id));

	if (ret<0)
		return -5;

	print_log(RSSLOG_LV_INFO, "D11 <TransferSessionID> %s\n", trans_id);
	close(sock);

	strcpy(trans_id_buf, trans_id);

	return 0;
	//return http_get_content(get_ip, get_port , trans_id, range);
	//return byte_sum;
	

}

int http_proxy_content(const char* host , int port , const char* uri ,int range , int send_sock)
{
	char header[2048];

	if (*uri=='/') uri++;
	int req_size = sprintf(header, "GET /%s HTTP/1.1\r\nHost: %s:%d\r\nTransfer-Delay: 0\r\nRange: bytes=%d-\r\nCdnInfo: downloadFile\r\nIngress-Capacity: 20000000\r\n\r\n",
		uri, host , port ,range );

	int sock = conn_srv( host , port );

	if (sock<0)
	{
		print_log( RSSLOG_LV_ERROR, "D11 connect %s:%d fail\n", host, port);
		return -3;
	}

	int maxbuff = 256 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&maxbuff, sizeof(maxbuff));

	maxbuff = 256 * 1024;
	setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, (char *)&maxbuff, sizeof(maxbuff));
	
	
	print_log(RSSLOG_LV_TRACE, "--------------SEND D11 GET REQ------------\n %s\n", header);
	writen(sock, header, strlen(header));
	
	char resp_buf[256*1024];
	int sum_read = 0;
	int sum_send = 0;
	int tmp_sum = 0;
	int ret , ret_send;
	
    //time_t start_ts, now_ts ;
	//start_ts = now_ts = time(NULL);        
 
	while ((ret = read_time( sock , resp_buf , sizeof(resp_buf) , 10000 ))>0) //3000ms  timeout
	{
		if (sum_read==0)
		{
			char resp[128] = {0};
			strncpy(resp, resp_buf, 128 );
			printf( "GET response :  %s\n", resp );
		}
		sum_read += ret ;
		
		tmp_sum += ret;
		if (tmp_sum > 2*1024*1024 )
		{
			print_log(RSSLOG_LV_TRACE, "recved %d KBytes\n", sum_read/1024);
			tmp_sum = 0;
		}
		
		int bytes = 0;
		ret_send = stable_send(send_sock , resp_buf, ret, &bytes);
		sum_send += bytes;
		
		if (ret_send<=0)
		{
			break;
		}

		/*
		now_ts = time(NULL);
		if (now_ts - start_ts > 300 )
		{
			print_log(RSSLOG_LV_TRACE,"recv timeout\n"); 
			break;
		}
		*/
	}
	print_log(RSSLOG_LV_INFO, "-- Total -- recved %d Bytes , send %d Bytes\n", sum_read, sum_send);
	close(sock);
	return sum_send;
}
/*
void connection_reading_d11_response(pn_connection_t *conn) 
{
    char buff[1024];
    int nrecv;
   
    //nrecv = read_response(conn->sock, buff, 1024);
    nrecv = read_time(conn->sock, buff, 1023, 30);
	
    if (nrecv > 0) {
		buff[1023]=0;
        pn_buffer_append_length(conn->d11_response, buff, nrecv);

		//printf("REQUEST: %s\n", conn->request->buff);
		
        if (pn_header_finish(conn->d11_response)) {
            pn_parse_header(conn);
            conn->stage = pn_writing_header_stage;
        }
    } else {
        print_log(RSSLOG_LV_ERROR , "cannot read data from connection ret %d, %s buf %s\n", nrecv, strerror(errno), conn->request->buff);
        //conn->stage = pn_closing_stage;
        conn->stage = pn_writing_header_stage;//IF the testclient error
    }
}
*/
pn_connection_t *connection_new(int sock , pn_connection_t* conn) {
    //pn_connection_t *conn;

	if (NULL==conn)
    	conn = malloc(sizeof(*conn));
	
    if (conn) {
        conn->sock      = sock;
        conn->keepalive = 0;
        conn->stage     = pn_reading_header_stage;
        conn->status    = pn_http_ok;
        conn->request   = pn_buffer_new( &conn->req_init );
        conn->response  = pn_buffer_new( &conn->res_init );
        conn->uri       = pn_buffer_new( &conn->uri_init );
		conn->d11_response = pn_buffer_new( &conn->d11_init);
        /*
         if (!conn->request || !conn->response || !conn->uri) {
            pn_buffer_free(conn->request);
            pn_buffer_free(conn->response);
            pn_buffer_free(conn->uri);
            free(conn);
            return NULL;
         
        }
        */
        return conn;
    }
   
    return NULL;
}

void connection_exit(pn_connection_t *conn) {
    /*
    if (conn->request)
        pn_buffer_free(conn->request);
    if (conn->response)
        pn_buffer_free(conn->response);
    if (conn->uri)
        pn_buffer_free(conn->uri);
     */
    //free(conn);
}

//宸ヤ綔绾跨▼
void *connection_thread_entrance(void *arg) {
    pn_connection_t *conn = (pn_connection_t *)arg;
   
    //pthread_detach(pthread_self());
   
    //fprintf(stderr, "[+] === pn thread working ===\n");
   
    while (1) {
        switch (conn->stage) {
	        case pn_reading_header_stage:
			case pn_continue_reading_header_stage:
	            connection_reading_header(conn);
	            break;
	        case pn_writing_header_stage:
				if (conn->method==pn_method_get || conn->method==pn_method_head)
	            	connection_make_get_header(conn);
				else
					connection_make_post_header(conn);
				
	            connection_send_header(conn);
	            break;
			case pn_writing_body_stage:
	            connection_send_body(conn);
				//connection_sendfile_body(conn);
	            break;
			case pn_writing_body_stage_thread:
				connection_exit(conn);
				goto THREAD_CLOSING;
				break;
	        case pn_closing_stage:
				//usleep(1000);
	            close(conn->sock);
	            connection_exit(conn);
	            goto THREAD_CLOSING;
	            break;
			case pn_d11_request_stage:
				//send_d11_request(const char * host, int port, const char * provider, const char * uni_content, const char * D11_type)
				break;
			case pn_d11_response_stage:
				break;
			default:
				print_log(RSSLOG_LV_ERROR, "unkown stage %d\n", conn->stage);
        }
    }

THREAD_CLOSING:
    //fprintf(stderr, "[-] === pn thread closing ===\n");
    //pthread_exit(NULL);

	return NULL;
}

int initialize_server(int port) {
    struct sockaddr_in addr;
    struct linger ling = {0, 0};
    int flags = 1;
   
    srv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_sock == -1)
        return -1;
    setsockopt(srv_sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(srv_sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    setsockopt(srv_sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
#if !defined(TCP_NOPUSH)
    setsockopt(srv_sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
#endif
   
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
   
    if (bind(srv_sock, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        return -1;
    if (listen(srv_sock, 2048) == -1)
        return -1;
    return srv_sock;
}

//缁戝畾CPU
int bind_thread_to_cpu(int index)
{
    int i;
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(index,  &mask);
    i = sched_setaffinity(0, sizeof(mask), &mask);
    if (i != 0)
        printf("ERR %s on CPU %d failed, %s\n", __func__, index,  strerror(errno));
        
    return (i == 0);
}


long long time_difference(struct timeval *t1, struct timeval *t2)
{
    /* t1 - t2 */

    return (long long)(t1->tv_sec) * 1000000 + t1->tv_usec - (long long)(t2->tv_sec) * 1000000 -
    t2->tv_usec;
}


atomic_t accept_thread_cnt = ATOMIC_INIT(0);
static pthread_mutex_t taglock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static int	cpu_num = 0;

void* socket_accept_thread(void *arg)
{
    int new_sock;
    socklen_t len;
    //struct sockaddr addr;
    struct sockaddr    addr;
	struct sockaddr_in addr_in;
    pn_connection_t *new_conn;

	pn_connection_t  conn_init;

	struct timeval now, start;

	long long d;
		
	char		    cip[20];
    //pthread_t tid;
    //pthread_attr_t pthread_attr;
    long long	thread_idx = (long long)arg;
	//int cpu_id = thread_idx % (cpu_num/3) + (cpu_num*2/3) ;
	int cpu_id = thread_idx % cpu_num;
	bind_thread_to_cpu(cpu_id);
	
	print_log(RSSLOG_LV_INFO, "thread %d start cpu %d\n", thread_idx, cpu_id );
    while (1) {

		len = sizeof(addr);

		atomic_inc(&accept_thread_cnt);
		pthread_mutex_lock(&taglock);
        new_sock = accept(srv_sock, &addr, &len);
		pthread_mutex_unlock(&taglock);
		atomic_dec(&accept_thread_cnt);
		
        if (new_sock == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
				print_log(RSSLOG_LV_ERROR, "accept error %d %s.\n", srv_sock, strerror(errno));

                continue;
            }
            break;
        }
	    gettimeofday(&start, 0);

		memcpy(&addr_in, &addr, sizeof(addr_in));
		inet_ntop(AF_INET, (void *)&addr_in.sin_addr, cip, sizeof(cip));
		print_log(RSSLOG_LV_INFO, "accept sock %d from %s:%d cnt %d\n", new_sock, cip, (int)ntohs(addr_in.sin_port), atomic_read(&accept_thread_cnt) );//PORT
        new_conn = connection_new(new_sock, &conn_init);
        if (!new_conn) {
            print_log(RSSLOG_LV_ERROR, "[x] pn not enough momery.\n");
            close(new_sock);
            break;
        }

		connection_thread_entrance(new_conn);

		gettimeofday(&now, 0);
		d = time_difference(&now, &start);

		if (d>300)
			print_log(RSSLOG_LV_WARNING, "process too long %lld us\n", d);

    }
	//ERROR_FLAG:
	print_log(RSSLOG_LV_ERROR, "[x] pn cannot accept client connection.\n");
	return NULL;
}




void socket_create_accept_thread(int thread_num) {

	    
		pthread_t tid;
		pthread_attr_t pthread_attr;

		long long i;
		cpu_num =  sysconf(_SC_NPROCESSORS_CONF);

		
		if (0==thread_num)
		{
			thread_num = cpu_num*10;

			if (thread_num<48)
				thread_num = 48;
		}
		
	    //pthread_create(&thread, &pthread_attr, sync_report_thread, (void *)arg);
		for (i=0 ; i<thread_num; i++) 
		{
			pthread_attr_init(&pthread_attr);
	    	pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);
		
			pthread_create(&tid,  &pthread_attr, socket_accept_thread , (void*)i);

			pthread_attr_destroy(&pthread_attr);
		}

		/*
		pthread_attr_init(&pthread_attr);
		pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);

		pthread_create(&tid,  &pthread_attr, sendfile_thread , NULL);

		pthread_attr_destroy(&pthread_attr);
		*/
//ERROR_FLAG:
//    fprintf(stderr, "[x] pn cannot accept client connection.\n");
    return;
}


void add_socket_accept_connection() {

	    long long i;
		pthread_t tid;
		pthread_attr_t pthread_attr;
		int watermark =  g_config.thread_num/4;

		int free_cnt =  atomic_read(&accept_thread_cnt);

		if (free_cnt>=watermark-1)
			return;

		print_log(RSSLOG_LV_INFO, "NOTICE add_socket_accept_connection() free_cnt %d low, add %d threads\n", free_cnt, watermark);
	    //pthread_create(&thread, &pthread_attr, sync_report_thread, (void *)arg);
		for (i=0 ; i<watermark; i++) 
		{
			pthread_attr_init(&pthread_attr);
	    	pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);
		
			pthread_create(&tid,  &pthread_attr, socket_accept_thread , (void*)i);

			pthread_attr_destroy(&pthread_attr);
		}
		
	   
	
        
    
//ERROR_FLAG:
//    fprintf(stderr, "[x] pn cannot accept client connection.\n");
    return;
}



void show_cfg();

void show_version();

int  read_cfg(const char * cfg_path);

int mysql_load_db(DB_CONFIG * db_cfg , struct obj_mem *cache );

void show_db_info(struct obj_mem *cache)
{
	int field = 0;
	
	print_log(RSSLOG_LV_INFO, "cache->obj_map_num %d\n", cache->obj_map_num );

	for (field = 0 ; field<10 ; field++)
	{
		
		printf( "%d:%d ", field, cache->start_index[field]);
	
		if (cache->start_index[field]<0) cache->start_index[field]=0;
	}
	printf("\n");
}





#define LOG_BUFFER_SIZE 128*1024
int main(int argc, char **argv) {
	char log_buf[LOG_BUFFER_SIZE] = {0} ;
	
    show_version();

    chdir("./");

	read_cfg("/usr/local/rss/dsim.cfg");
	show_cfg();
	
	memset(&g_local, 0 ,sizeof(g_local));
	memset(&g_cache, 0 ,sizeof(g_cache));
	//mysql_load_db(&g_db_cfg_local, &g_local);
	//mysql_load_db(&g_db_cfg_cache, &g_cache);

	 	


    if (initialize_server(g_config.http_port) == -1) {
        fprintf(stderr, "[ERROR] pn initialize failed. %s [ERROR]\n", strerror(errno));
        exit(1);
    }
	printf("http listened %d\n", g_config.http_port);

	int thread = 1;

	if (!(argc>1 && 0==strcmp(argv[1], "-c")) ) //not dsim -c
	{
		daemon(0,0);
		thread = g_config.thread_num;
	}
	g_config.thread_num = thread;

	show_version();

	show_db_info(&g_local);
	show_db_info(&g_cache);
	
    socket_create_accept_thread(thread);
	
	sleep(1);
	show_cfg();
	

	setbuffer(stdout, log_buf, LOG_BUFFER_SIZE);
	while(1)
	{
		fflush(stdout);
		logSize = 0;
		add_socket_accept_connection();
		sleep(1);
	}
    return 0;
}

//---------------------------------------------------------------------
/*
  ============================================================================
  Name        : mysql_test
  Author      : 
  Version     :
  Copyright   : Your copyright notice
  Description : Hello World in C, Ansi-style
  ============================================================================
  */
 
const char* find_uri_byid(const char* obj_id , const struct obj_mem *objm, int nn_factor, int isNeedRef)
{
	int i;
	uid_type_t id_int = _atouid(obj_id);

	int	result1 = -1;
	int result2 = -1;

	int field1 = 0 , field2 = 0;
	
	field1 = get_id_field(obj_id);

	int start_idx = objm->start_index[field1];

	//if (id_int>0)
	{
		//search int is more faster
		for(i=start_idx ; i<objm->obj_map_num ; i++)
		{
			if (id_int == objm->id_list[i])
            {    
                //printf("%u finded %d\n", id_int, i);
				if (0==strcmp(obj_id , objm->obj_map_list[i].obj_id))
				{
					result1 = i;
					if(0==isNeedRef)
					{
						printf("NOTICE find_uri_byid() objid %s isNeedRef %d\n", obj_id, isNeedRef );
						return objm->obj_map_list[result1].uri;			
					}
					break;
				}
			}
            		//return g_obj_map_list[i].uri;
		}
	}
	/*
	else
	{
		for(i=0;i<objm->obj_map_num;i++)
		{
			//string search is slower
			if (0==strcmp(obj_id , objm->obj_map_list[i].obj_id))
			{
				result1 = i;
				break;
				//return g_obj_map_list[i].uri;
			}	
		}		
	}
	*/
	if (result1<0)
		return NULL;

	//return g_obj_map_list[2567].uri;

	result2 = result1 / nn_factor  *  nn_factor;

	
	//field1 = get_id_field(objm->obj_map_list[result1].obj_id);
	field2 = get_id_field(objm->obj_map_list[result2].obj_id);

	//if (field1!=2101 && field1!=2201)
	//	print_log(RSSLOG_LV_ERROR, "INVALID field  %d vs %d %s\n", field1, field2, obj_id);
	
	if (field2!=field1)
	{
		print_log(RSSLOG_LV_INFO, "not corrct %d:%d vs %d:%d %s\n",result1, field1, result2, field2, obj_id);
		result2 = objm->start_index[field1];

		field2 = get_id_field(objm->obj_map_list[result2].obj_id);
		if (field2!=field1)
		{
			result2 = result1;
			print_log(RSSLOG_LV_ERROR, "something worong not corrct %d:%d vs %d:%d %s\n",result1, field1, result2, field2, obj_id);
		}
	}
	 
	return objm->obj_map_list[result2].uri;
}

/* 
MYSQL *g_conn; // mysql 杩炴帴
MYSQL_RES *g_res; // mysql 璁板綍闆?
MYSQL_ROW g_row; // 瀛楃涓叉暟缁勶紝mysql 璁板綍琛?
*/
  
#define MAX_BUF_SIZE 1024 // 缂撳啿鍖烘渶澶у瓧鑺傛暟


void set_default_cfg()
{
	/* define default values */
	memset((char *)&g_config, 0, sizeof(g_config));
	
	strcpy(g_db_cfg_local.mysql_db_name,"mddb");
	strcpy(g_db_cfg_local.mysql_pass,"root");
	strcpy(g_db_cfg_local.mysql_user,"root");
	strcpy(g_db_cfg_local.mysql_host, "172.16.65.11");
	g_db_cfg_local.mysql_db_port = 3306;

	
	g_config.http_port = 1080;
	g_config.nn_factor = 1;

	//strcpy(g_config.id_mask,"0000000000000000002%");

	g_config.pull_port_num = 24;
	g_config.dsi_pull_mod = 0;
	g_config.proxy_rate = 0;
	strcpy(g_config.dsi_host, "172.16.65.144");
	strcpy(g_config.dsi_host_2, "172.16.65.145");
	g_config.active_host_fail = 0;

	strcpy(g_config.upper_cdn_host, "10.50.77.102");
	g_config.upper_cdn_port = 8007;
	g_config.thread_num = 24*5;

	g_config.dsi_port= DSIWK_PORT;
	g_config.stress_interval_ms = 1500;
	
}

void show_cfg()
{

	printf("*****CONFIG*****\n");
	printf("local db %s:%d(%s) user %s pass %s\n",
		g_db_cfg_local.mysql_host, g_db_cfg_local.mysql_db_port, g_db_cfg_local.mysql_db_name,
			g_db_cfg_local.mysql_user, g_db_cfg_local.mysql_pass);
	
	printf("cache db %s:%d(%s) user %s pass %s\n",
		g_db_cfg_cache.mysql_host, g_db_cfg_cache.mysql_db_port, g_db_cfg_cache.mysql_db_name,
			g_db_cfg_cache.mysql_user, g_db_cfg_cache.mysql_pass);

	
	printf("listenPort %d factor %d pull_process_num %d dsiwk_pull %d proxyrate %d\n",
		 g_config.http_port, g_config.nn_factor, g_config.pull_port_num, g_config.dsi_pull_mod , g_config.proxy_rate);

	printf("UPPER_HOST %s UPPER_PORT %d\n", g_config.upper_cdn_host, g_config.upper_cdn_port);
	printf("THREAD_NUM=%d\n", g_config.thread_num );

	printf("DSI_HOST=%s  DSI_HOST_2=%s  DSI_PORT=%d\n", g_config.dsi_host,g_config.dsi_host_2, g_config.dsi_port); 

	printf("STRESS_INTERVAL=%d\n", g_config.stress_interval_ms );
		
	if(g_config.nn_factor==0)
		g_config.nn_factor = 1;
	

}

void show_version()
{
	printf("dsim version: V1.5 build date:%s, time: %s\n", __DATE__, __TIME__);
	printf("1.5 - use field to speed search\n"); 
	printf("1.6 - 150ms timeout & 6 x cpu thread\n"); 
	printf("1.7 - support ctc test\n");
	printf("1.8 - support multi birate\n");
	printf("1.9 - support httpdownload / GET isNeedRef birate\n");
	printf("1.9b - support D11 isNeedRef birate\n");
	printf("1.91 - add DSI_PORT , fix safe_strncpy bug\n");
	printf("2.0a - Support HA switch , add DSI_HOST2\n");
	printf("2.1 -  Support huawei & cisco provider ID\n");
}

int read_cfg(const char* cfg_path) 
{
	 FILE *fp=NULL;
	 char line[512];

	 char *pVar;
	 char *pVal;
 
	 set_default_cfg();

	 /* try to open the config file */

	fp=fopen(cfg_path, "r");
	
	if (fp==NULL) {
		 printf("read cfg %s error %s\n", cfg_path, strerror(errno));
		 return -1;

	 }


	 while (fgets(line, sizeof(line)-1, fp)!=NULL) {
		 while ((line[strlen(line)-1]=='\n')||(line[strlen(line)-1]=='\r')) {
			 line[strlen(line)-1]='\0';
		 }
		 if (isalpha(line[0])) {
			 pVar=line;
			 pVal=line;

			 while ((*pVal!='=')&&((char *)&pVal+1!='\0')) pVal++;
			 
			 *pVal='\0';
			 pVal++;
			 while (*pVar==' ') pVar++;
			 while (pVar[strlen(pVar)-1]==' ') pVar[strlen(pVar)-1]='\0';
			 while (*pVal==' ') pVal++;
			 while (pVal[strlen(pVal)-1]==' ') pVal[strlen(pVal)-1]='\0';
			 while (*pVal=='"') pVal++;
			 while (pVal[strlen(pVal)-1]=='"') pVal[strlen(pVal)-1]='\0';

			 // for local db config
			 if (strcmp(pVar, "MYSQL_HOST")==0) {
				 safe_strncpy(g_db_cfg_local.mysql_host, pVal, sizeof(g_db_cfg_local.mysql_host));
			 } else if (strcmp(pVar, "MYSQL_PORT")==0) {
				 g_db_cfg_local.mysql_db_port = atoi(pVal);
			 } else if (strcmp(pVar, "MYSQL_USER")==0) {
				 safe_strncpy(g_db_cfg_local.mysql_user, pVal, sizeof(g_db_cfg_local.mysql_user));
			 } else if (strcmp(pVar, "MYSQL_PASS")==0) {
				 safe_strncpy(g_db_cfg_local.mysql_pass, pVal, sizeof(g_db_cfg_local.mysql_pass));
			 } else if (strcmp(pVar, "MYSQL_DBNAME")==0) {
				 safe_strncpy(g_db_cfg_local.mysql_db_name, pVal, sizeof(g_db_cfg_local.mysql_db_name));
			 } 

		     //for cache db config
			 else if  (strcmp(pVar, "CACHE_MYSQL_HOST")==0) {
				 safe_strncpy(g_db_cfg_cache.mysql_host, pVal, sizeof(g_db_cfg_cache.mysql_host));
			 } else if (strcmp(pVar, "CACHE_MYSQL_PORT")==0) {
				 g_db_cfg_cache.mysql_db_port = atoi(pVal);
			 } else if (strcmp(pVar, "CACHE_MYSQL_USER")==0) {
				 safe_strncpy(g_db_cfg_cache.mysql_user, pVal, sizeof(g_db_cfg_cache.mysql_user));
			 } else if (strcmp(pVar, "CACHE_MYSQL_PASS")==0) {
				 safe_strncpy(g_db_cfg_cache.mysql_pass, pVal, sizeof(g_db_cfg_cache.mysql_pass));
			 } else if (strcmp(pVar, "CACHE_MYSQL_DBNAME")==0) {
				 safe_strncpy(g_db_cfg_cache.mysql_db_name, pVal, sizeof(g_db_cfg_cache.mysql_db_name));
			 } 

		     //else config
			 else if (strcmp(pVar, "HTTP_PORT")==0) {
				 g_config.http_port = atoi(pVal);
			 } else if (strcmp(pVar, "NN_FACTOR")==0) {
				 g_config.nn_factor = atoi(pVal);
			 }
			 else if (strcmp(pVar, "PULL_PORT_NUM")==0) {
				 g_config.pull_port_num = atoi(pVal);
			 }
			 else if (strcmp(pVar, "DSIWK_PULL")==0) {
				 g_config.dsi_pull_mod= atoi(pVal);
			 }
			 else if (strcmp(pVar, "PROXY_RATE")==0) {
				 g_config.proxy_rate = atoi(pVal);
			 }
			 else if (strcmp(pVar, "DSI_HOST")==0) {
				 safe_strncpy(g_config.dsi_host, pVal, sizeof(g_config.dsi_host));
			 }
			 else if (strcmp(pVar, "DSI_HOST_2")==0) {
				 safe_strncpy(g_config.dsi_host_2, pVal, sizeof(g_config.dsi_host_2));
			 }
			 else if (strcmp(pVar, "UPPER_HOST")==0) {
				 safe_strncpy(g_config.upper_cdn_host, pVal, sizeof(g_config.upper_cdn_host));
			 }
			 else if (strcmp(pVar, "UPPER_PORT")==0) {
				 g_config.upper_cdn_port= atoi(pVal);
			 }
			 else if (strcmp(pVar, "THREAD_NUM")==0) {
				 g_config.thread_num= atoi(pVal);
			 }
			 else if (strcmp(pVar, "DSI_PORT")==0) {
			 	 printf("%s\n", pVal );
				 g_config.dsi_port= atoi(pVal);
			 }
			 else if (strcmp(pVar, "STRESS_INTERVAL")==0) {
			 	 g_config.stress_interval_ms = atoi(pVal);
			 }			 
			 else
			 	printf("unknown var %s val %s\n", pVar, pVal);
			 *pVal='\0';
			 *pVar='\0';
		 }
	 }
	 fclose(fp);
	 
	 return 0;
 }

#if 0 
 void print_mysql_error(const char *msg) { // 鎵撳嵃鏈€鍚庝竴娆￠敊璇?
     if (msg)
         printf("ERR: *************MYSQL*************  %s: %s\n", msg, mysql_error(g_conn));
     else
         puts(mysql_error(g_conn));
 }
 
 int executesql(const char * sql) {
     /*query the database according the sql*/
     if (mysql_real_query(g_conn, sql, strlen(sql))) // 濡傛灉澶辫触
         return -1; // 琛ㄧず澶辫触
 
     return 0; // 鎴愬姛鎵ц
 }
 
 
 int init_mysql(DB_CONFIG * db_cfg) { // 鍒濆鍖栬繛鎺?

	 // init the database connection
     g_conn = mysql_init(NULL);
 
     /* connect the database */
     if(!mysql_real_connect(g_conn, db_cfg->mysql_host, db_cfg->mysql_user, db_cfg->mysql_pass, 
	 		db_cfg->mysql_db_name, db_cfg->mysql_db_port, NULL, 0)) // 濡傛灉澶辫触
     {
		return -1;
     }
     // 鏄惁杩炴帴宸茬粡鍙敤
     if (executesql("set names utf8")) // 濡傛灉澶辫触
         return -1;

	 printf("mysql connected\n");
     return 0; // 杩斿洖鎴愬姛
 }
 
 
 int mysql_load_db(DB_CONFIG * db_cfg , struct obj_mem *cache ) {


	 if (db_cfg->mysql_db_port<=0) // if don't config mysql port , we don't load mysql db
	 	return -1;

     if (init_mysql(db_cfg)) 
     {
	 	print_mysql_error(" init_mysql() ");
 		exit(1);
     }
     //domain  : 0-IPTV锛?1-PC锛?2-Mobile
     //object_type : 1 VOD  
     char sql[MAX_BUF_SIZE]="select object_id,object_type, http_uri from mddb.objects_map where object_type=1 and providerID LIKE \"ut%\" order by substring(object_id,32) , object_id";

	//spirntf(sql, "select object_id,object_type, http_uri from mddb.objects_map where domain=1 and ProviderID='UT' and object_type=1 and object_id like '%s'",
	//	g_config.id_mask);

	
     /*
     sprintf(sql, "INSERT INTO `test`(`name`) VALUES('testname')");
 
     if (executesql(sql))
         print_mysql_error(NULL);
 	*/
     if (executesql(sql)) // 鍙ユ湯娌℃湁鍒嗗彿
     {
     	print_mysql_error( " executesql() " );
		exit(1);
     }

     g_res = mysql_store_result(g_conn); // 浠庢湇鍔″櫒浼犻€佺粨鏋滈泦鑷虫湰鍦帮紝mysql_use_result鐩存帴浣跨敤鏈嶅姟鍣ㄤ笂鐨勮褰曢泦
 
     int iNum_rows = mysql_num_rows(g_res); // 寰楀埌璁板綍鐨勮鏁?
     int iNum_fields = mysql_num_fields(g_res); // 寰楀埌璁板綍鐨勫垪鏁?
 
     printf("**********objmap total %d records**********	%d fields per row\n", iNum_rows, iNum_fields);

	 int field;
	 
 	 cache->obj_map_num = 0;
	 for (field = 0 ; field<10 ; field++)
	 	cache->start_index[field] = -1;

	 
     while ((g_row=mysql_fetch_row(g_res))) // 鎵撳嵃缁撴灉闆?
     {
     	//int field_id = 0;
     	//printf("%s\t%s\t%s \n", g_row[0], g_row[1], g_row[2]); // 绗竴锛岀浜屽瓧娈?

		
		field = get_id_field(g_row[0]);

		//if (cache->obj_map_num<10)
		//	printf("%d - field %d uid %s\n",cache->obj_map_num, field, g_row[0]);
		
		if (cache->start_index[field]<0)
		{
			cache->start_index[field] = cache->obj_map_num;
			printf("%d - field %d uid %s\n",cache->obj_map_num, field, g_row[0]);
		}
		safe_strncpy(cache->obj_map_list[cache->obj_map_num].obj_id, g_row[0], 256);
	        
		cache->id_list[cache->obj_map_num] = _atouid(g_row[0]);

		safe_strncpy(cache->obj_map_list[cache->obj_map_num].uri, g_row[2], 256);
		

		cache->obj_map_num++;
		if (cache->obj_map_num>=MAX_OBJMAP_NUM)
		{	
			printf("WARN : max num of obj map overflow! %d\n", iNum_rows);
			break;
		}
	 }

 	for (field = 0 ; field<10 ; field++)
	{
		
		printf("%d:%d ", field, cache->start_index[field]);

		if (cache->start_index[field]<0) cache->start_index[field]=0;
 	}
	cache->start_index[0]=0;
	printf("\n");
    mysql_free_result(g_res); // 閲婃斁缁撴灉闆?
 
    mysql_close(g_conn); // 鍏抽棴閾炬帴
 
     return EXIT_SUCCESS;
 }



#endif

