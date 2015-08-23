#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <assert.h>
#include <time.h>
#include <assert.h>

#include <windows.h>

#define _P_DEBUG_
#define U32_RABBISH  0xCCCCCCCC

#ifdef _P_DEBUG_
  #define COUNT_VERIFY  assert
  #define COUNT_ASSERT  assert
  #define COUNT_TRACE    printf
#else
  #define COUNT_VERIFY  
  #define COUNT_ASSERT  
  #define COUNT_TRACE    
#endif

#ifndef uint32_t
typedef unsigned char  uint8_t;
typedef signed short  int8_t;
typedef unsigned short  uint16_t;
typedef signed short  int16_t;
typedef unsigned int  uint32_t;
typedef signed int    int32_t;
#endif

typedef struct _tag_stVisit
{
  int reserve;
} stVisit;

typedef struct _tag_ip_entry
{
  struct _tag_ip_entry* next;
  uint32_t  ip;
  stVisit*  key2nd;
  uint32_t  watch_dog1;
  uint32_t  watch_dog2;
}ip_entry;

uint32_t get_hash_index( uint32_t key )
{
  //return (key* 2654435761UL) & HASH_TAB_MASK_4_1024;
  uint32_t ret = (key* 2654435761UL) >>(32-10);
  return ret;
}

static ip_entry*  hash_table[1024] = {0};

#define MAX_AVLB_COUNT  1024
static ip_entry* g_avail_head = NULL;
static int      g_avail_list_num = 0;

/***********************************************
* if we have avalid free node , return it , otherwise we malloc it
***********************************************/
ip_entry* ip_entry_new_node()
{
  ip_entry* entry = g_avail_head;

  if (NULL==g_avail_head)
  {
    COUNT_VERIFY(g_avail_list_num==0);
    entry = (ip_entry*)malloc(sizeof(ip_entry));
    COUNT_VERIFY(entry);
    COUNT_TRACE("new node alloc at %08x\n", entry);

    memset( entry, 0xCC, sizeof(ip_entry));
    return entry;
  }
  
  g_avail_list_num--;
  COUNT_VERIFY(g_avail_list_num>=0);
  if (g_avail_list_num<0)
  {
    g_avail_list_num=0;
  }

  g_avail_head = g_avail_head->next;

  COUNT_VERIFY(U32_RABBISH==entry->ip && U32_RABBISH==(uint32_t)entry->key2nd && U32_RABBISH==entry->watch_dog1 && U32_RABBISH==entry->watch_dog2 );
  //memset( entry->ientry , 0xCC, sizeof(ip_entry)-4);
  return entry;
}

/***********************************************
* return node to free list , or free it
***********************************************/
void ip_entry_free_node(ip_entry** prev_next,  ip_entry* entry)
{
  COUNT_VERIFY(g_avail_list_num>=0 && g_avail_list_num<=MAX_AVLB_COUNT);
  COUNT_VERIFY(U32_RABBISH!=entry->ip && U32_RABBISH!=(uint32_t)entry->key2nd && U32_RABBISH!=entry->watch_dog1 && U32_RABBISH!=entry->watch_dog2 );

  *prev_next = entry->next;
  
  if (g_avail_list_num>=MAX_AVLB_COUNT)
  {
    COUNT_TRACE("free node at %08x\n", entry);
    free(entry);
    return;//too much free node , free to to heap
  }
#ifdef _P_DEBUG_
  memset( &entry->ip , 0xCC, sizeof(ip_entry)-4);
#endif
  //put it to avail_head
  entry->next = g_avail_head;
  g_avail_head = entry;
  
  g_avail_list_num++;

  return;  
}

ip_entry* find_entry(uint32_t ip)
{
  
  ip_entry* same_entry = NULL , *tmp_entry=NULL;
  
  int index = get_hash_index(ip);
  ip_entry* entry = hash_table[index];
  ip_entry** prev = &hash_table[index];

  while(entry!=NULL)
  {
    COUNT_VERIFY(U32_RABBISH!=entry->ip && U32_RABBISH!=(uint32_t)entry->key2nd && U32_RABBISH!=entry->watch_dog1 && U32_RABBISH!=entry->watch_dog2 );
    COUNT_VERIFY( get_hash_index(entry->ip)==index );
    if (0 && "put you delete condition here" )
    {
      tmp_entry = entry;
      entry = entry->next;
      ip_entry_free_node( prev, tmp_entry );      
      
      continue;
    }

    if (entry->ip == ip)
    {
      same_entry = entry;
      break; //we found it!
    }
    COUNT_VERIFY(entry != entry->next);
    prev = &(entry->next);
    entry = entry->next;
  } //end while

  if (same_entry==NULL)
  {
    //not found , alloc new ip entry
    same_entry = ip_entry_new_node();
    COUNT_VERIFY(same_entry);

    if (NULL==same_entry)
      return same_entry;

    same_entry->ip = ip;
    same_entry->key2nd = malloc( sizeof(stVisit) );
    same_entry->watch_dog1 = 0;
    same_entry->watch_dog2 = 0;

    //put to hash list head
    same_entry->next = hash_table[index];
    hash_table[index] = same_entry;
  }
  
  return same_entry;
}


int main()
{
  uint32_t ip ;
  int  i;
  ip_entry* tmp ;

  int count[2048] = {0} ;
  for (i=0 ; i <10000*10000; i++)
  {
    ip = rand();

    tmp = find_entry(ip );
    printf("ip %08x \n",  ip);
  }
  
  return 0;
}