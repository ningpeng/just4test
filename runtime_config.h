/*

    
*/



#ifndef __RUNTIME_CONFIG_H__
#define __RUNTIME_CONFIG_H__

#include <sys/cdefs.h>

__BEGIN_DECLS  

//#define CONFIG_FILE "configurations"

//how to use :  see test_runtime_cfg.c

#define SET_DEFAULT_INT_CONFIG(X) set_configuration_number_default(#X, (int)(X));
#define SET_DEFAULT_NUM_CONFIG(X) set_configuration_number_default(#X, (X));
#define SET_DEFAULT_STR_CONFIG(X) set_configuration_string_default(#X, (X));

int update_configuration(void);
int initialize_config_file(const char *name);
 
int set_configuration_string(const char *key, const char *value);
int set_configuration_string_default(const char *key, const char *value);
int set_configuration_number(const char *key, double value);
int set_configuration_number_default(const char *key, double value);
int get_configuration_string(const char *key, char *value, int value_len);
int get_configuration_number(const char *key, double *value);

double get_config_num(const char *key);

#define CONFIG_VALUE(X) get_config_num(#X)

__END_DECLS


#endif

