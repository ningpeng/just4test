/*
    Copyright PP, Inc.
    
    
*/


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>


#include "runtime_config.h"


#define MAX_NUM_CONFIGS 10000
#define CFG_PATH_MAX        2048


#define _CFG_LOG_ERR    printf
#define _CFG_LOG_WRN    printf
#define _CFG_LOG_DEBUG  printf
#define _CFG_LOG_INFO   printf

static char _config_file_name[CFG_PATH_MAX] = { 0 } ;
 
typedef struct lines
{
    char *key;
    char *value;
} config_entry;

int initialize_config_file(const char *name)
{
    strncpy(_config_file_name, name, CFG_PATH_MAX-1);
    _config_file_name[CFG_PATH_MAX-1] = 0;
    return 1;
}



static int updated = 0;
static config_entry configs[MAX_NUM_CONFIGS] = { {0, 0} };

#ifdef LINUX
	 static pthread_mutex_t lock=PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
	 static pthread_mutex_t lock;
#endif

static void log_file_lock(void)
{
	pthread_mutex_lock(&lock);
}

static void log_file_unlock(void)
{
	pthread_mutex_unlock(&lock);
}


#define LOCK log_file_lock();

#define UNLOCK log_file_unlock();

static void free_configs(void)
{
    int i;
    for (i = 0; i < sizeof(configs) / sizeof(configs[0]); i++)
    {
        if (configs[i].key)
            free(configs[i].key);
        if (configs[i].value)
            free(configs[i].value);
    }

    memset(configs, 0, sizeof(configs));
}


static config_entry *get_entry(const char *key)
{
    int i;
    for (i = 0; (i < sizeof(configs) / sizeof(configs[0])) && (configs[i].value != 0); i++) 
    {
        if (configs[i].key == 0) 
            continue;
        if (!strcmp(key, configs[i].key))
            return configs + i;
    }
    return 0;
}
    
static void append_entry(const char *key, const char *value)
{
    int i;
    for (i = 0; (i < sizeof(configs) / sizeof(configs[0])) && (configs[i].value != 0); i++) 
        ;
    if (i ==  sizeof(configs) / sizeof(configs[0]))
        /* overflow */
        return;
    if (key)       
        configs[i].key = strdup(key);
    if (value && strlen(value))
        configs[i].value = strdup(value);
    else
        configs[i].value = 0;
}    
    
static int is_string_all_space(const char* s)
{
    const char *c = s;
    //rss_warning(c);
    if (!c)
        return 1;
    if (*c == 0)
        return 1;
    while (*c)
    {
        if (isspace(*c) == 0)
            return 0;
        c++;
    }
    return 1;
}
    
static int read_configs(void)
{
    int i;
    char buf[2000], *sep;
    FILE *f;
	LOCK
    f = fopen(_config_file_name    , "r");
    free_configs();
    if (!f)
	{
        UNLOCK
        return 0;
    }
    i = 0;
    while (fgets(buf, sizeof(buf), f))
    {
        if (is_string_all_space(buf))
            continue;
        if (buf[strlen(buf) - 1] == '\n')
            buf[strlen(buf) - 1] = 0;
        
        if (buf[0] == '#')
        {
             /* allow comments */
            configs[i].value = strdup(buf);  
            i++;  
            continue;
        }
        sep = strchr(buf, '=');
        if (sep)
        {
            *sep = 0;
            sep++;
	        if (sep[strlen(sep) - 1] == '\n')
                    sep[strlen(sep) - 1] = 0;

            configs[i].value = strdup(sep);    
        }
        configs[i].key = strdup(buf);
        i++;
    }
    fclose(f);
	UNLOCK
    /*_CFG_LOG_INFO("Re-read configuration file %s\n", _config_file_name    );*/
    return 1;
}

static int write_configs(void)
{
    int stuffed, i;
    FILE *f;
    LOCK
    f = fopen(_config_file_name    , "w");
    

    if (!f)
    {
	    UNLOCK
	    _CFG_LOG_INFO("writing %s failed\n", _config_file_name    );
        return 0;
    }
    for (i = 0; (i < sizeof(configs) / sizeof(configs[0])) ; i++) 
    {
        stuffed = 0;
        if (configs[i].key)
        {
            fprintf(f, "%s=", configs[i].key);
            stuffed = 1;
        }
        if (configs[i].value)
        {
            fprintf(f, "%s", configs[i].value);
            stuffed = 1;
        }
        if (stuffed)
            fprintf(f, "\n");
    }
    fclose(f);
	UNLOCK
    return 1;
}

int update_configuration(void)
{
  
    static int init_written = 0;
    if (init_written == 0)
    {
        init_written = 1;
        write_configs();
    }


    updated = 0;
    return 1;
}


int set_configuration_string(const char *key, const char *value)
{
    config_entry *entry = 0;
    read_configs();
    entry = get_entry(key);
    if (!entry)
        append_entry(key, value);
    else
    {
        free(entry->value);
        entry->value = strdup(value);
    }
    write_configs();
    return 1;
}


int set_configuration_string_default(const char *key, const char *value)
{
    config_entry *entry = 0;
    read_configs();
    entry = get_entry(key);
    if (!entry)
        append_entry(key, value);
    else
        return 0;
    write_configs();
    return 1;
}

int set_configuration_number(const char *key, double value)
{
    char buf[100];
    sprintf(buf, "%lf", value);
    return set_configuration_string(key, buf);
}    

int set_configuration_number_default(const char *key, double value)
{
    char buf[100];
    sprintf(buf, "%lf", value);
    return set_configuration_string_default(key, buf);
}    


int get_configuration_string(const char *key, char *value, int value_len)
{
    config_entry *entry = 0;
    int i;
    if (!updated)
    {
        read_configs();
        updated = 1;
    }  
    entry = get_entry(key);
    if (!entry)
        return 0;
    else
    {
        strncpy(value, entry->value, value_len);
        for (i = strlen(value) - 1; value[i] && (i >= 0); i--)
            if (isspace(value[i])) 
                value[i] = 0; /* remove tail spaces */

    }
    return 1;
}

 
            
int get_configuration_number(const char *key, double *value)
{
    char buf[200];
    int r, i;
    r = get_configuration_string(key, buf, sizeof(buf));
    if (r)
    {
        i = sscanf(buf, "%lf", value);
        if (!i)
            return 0;
    }
    return r;
}

double get_config_num(const char *key)
{
    double f = 0;
    int i = get_configuration_number(key, &f);
    if (i == 0)
    {
        _CFG_LOG_WRN("getting configuration value of %s failed, return 0 as default\n", key);
    }
    return f;
}


