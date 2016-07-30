#include <stdio.h>
#include <assert.h>

#ifndef OFFSET_OF
#define OFFSET_OF(type, memb) \
	((unsigned long)(&((type *)0)->memb))
#endif
#ifndef CONTAINER_OF
#define CONTAINER_OF(obj, type, memb) \
	((type *)(((char *)obj) - OFFSET_OF(type, memb)))
#endif


typedef struct _slist_node {
	struct _slist_node *next;
} slist_node;

typedef struct _pn_hash_table
{
	slist_node*		bucket;
	size_t			table_size;

}pn_hash_table;

typedef struct _pn_hash_node
{
	slist_node slist_next;
	
	int		key;
	void*	data;

} pn_hash_node;


#define TO_PN_HASH_NODE(x) CONTAINER_OF(x, struct _pn_hash_node, slist_next);

pn_hash_node* pn_hash_node_new()
{
	return malloc( sizeof(pn_hash_node) );
}

void pn_hash_node_free(pn_hash_node* node)
{
	assert(node);
	free ( node );
}


/******************************************
*  Describe:  init hash_tablem , 
*  PARAM:
*		size : the bucket size
*  RETURN:
*		void
******************************************/
void pn_hash_table_init(pn_hash_table* table , size_t size)
{
	assert( table!=NULL);
	assert( size >0 );
	table->bucket = (slist_node*)calloc( sizeof(slist_node) , size );
	table->table_size = size;

	return;
}


/******************************************
*  Describe:  find prev slist_node by key , 
*  PARAM:
*		in  key : the key to find
*		out prev_node : the slist_node to be returned , it will be the prev node  ( slist->next ->key == key )
*  RETURN:
*		0 , success find the hash_node , the out_node will be the prev node of the node finded
*		<0, not find the hash_node , the out_node will be the hash bucket list head
******************************************/
int pn_hash_find_prev_node(int key ,  slist_node* prev_node , const pn_hash_table *table )
{
	int hash = key % (table->table_size);
	int ret = -1;

	slist_node*  hnode = &(table->bucket[hash]);
	slist_node*  prev = hnode;

	while( (hnode = hnode->next)!= NULL )
	{
		pn_hash_node  *data_node =  TO_PN_HASH_NODE( hnode );
		if (data_node->key == key)
		{
			break;
		}
		prev = hnode;
	}

	*prev_node = *prev;
	if (hnode)
	{
		return 0;
	}
	return -1; //not found
}

int pn_hash_find( int key , void** p_data , const pn_hash_table *table)
{
	slist_node node;
	pn_hash_node  *data_node;

	
	int ret = pn_hash_find_prev_node(key, &node, table);

	if (ret==0)
	{
		assert(node.next);
		data_node =  TO_PN_HASH_NODE( &(node.next) );
		*p_data = data_node->data;
	}
	return ret;
}

//found_action 0:  if key exist, insert fail , return -1;
//found_action 1:  if key exist, just update
//found_action 2:  if key exist, insert a new item ( allow duplicate )
//--------------------------------------------------------------------------
//not_found_action 0: if key non-exist ,  insert it
//not_found_action 1: if key non-exist ,  not insert , return -1
int _pn_hash_setex(int key,  void* data, pn_hash_table *table, int found_action , int not_found_action)
{
	slist_node node;
	pn_hash_node  *data_node;

	int ret = pn_hash_find_prev_node(key, &node, table);

	if (ret <0)
	{
		//NOT FOUND
		if (not_found_action==0)
		{
			assert(node.next == NULL);
			//not found , just insert it
			data_node = pn_hash_node_new();
			data_node->key = key;
			data_node->data = data;
			data_node->slist_next.next = NULL;
			
			node.next = &(data_node->slist_next);
		}
		else
		{
			return -1;
		}

	}
	else
	{
		//found the key
		assert(node.next);

		if (found_action==1)
		{
			//just update the data
			data_node = TO_PN_HASH_NODE( node.next );
			assert(data_node);

			data_node->data = data;
		}
		else if (found_action==0)
		{
			//insert failure
			return -1;
		}
		else if (found_action==2)
		{
			//insert a dup key ( like multimap )
			data_node = pn_hash_node_new();
			data_node->key = key;
			data_node->data = data;
			data_node->slist_next.next = node.next;
			
			node.next = &(data_node->slist_next);
		}
		else
		{
			assert( "invalid action value" && 0 );
		}
	}

	return 0;
}

/******************************************
*  Describe:  try to insert a new (key-data) pair,
*				if (find dup key-data pair) then { return failure  } 
*				else {  insert new pair when not found  and return success } 
*  PARAM:
*		[in]  key : the key to find
*		[in]  data : the data to be update
*  RETURN:
*		0 , success insert the new hash_node 
*		<0, find the dup key in hash_table
******************************************/
int pn_hash_insert(int key,  void* data, pn_hash_table *table)
{
	return _pn_hash_setex(key, data, table, 0 , 0);
}

/******************************************
*  Describe:   Insert new hash_node regardless of whether the key is found.
*				if (key found)
					insert new key before it
				else
					insert new key
*  PARAM:
*		[in]  key : the key to find
*		[in]  data : the data to be update
*  RETURN:
*		0 , success insert the hash_node 
*		<0, insert failure
******************************************/
int pn_hash_dup_insert(int key,  void* data, pn_hash_table *table)
{
	return  _pn_hash_setex(key, data, table, 2 , 1);
}

/******************************************
*  Describe:  update the data value when find key,
*				or insert new key-data pair when not found 
*
*  PARAM:
*		[in]  key : the key to find
*		[in] data : the data to be update
*  RETURN:
*		0 , success find the hash_node 
*		<0, error : insert/update failure
******************************************/
int pn_hash_ins_update(int key,  void* data, pn_hash_table *table)
{
	return  _pn_hash_setex(key, data, table, 1 , 1);
}

/******************************************
*  Describe:  update the data value when find key,
*				or do nothing and ret failure when not found 
*
*  PARAM:
*		[in]  key : the key to find
*		[in]  data : the data to be update
*  RETURN:
*		0 , success find the hash_node 
*		<0, error : not find key
******************************************/
int pn_hash_update(int key,  void* data, pn_hash_table *table)
{
	return  _pn_hash_setex(key, data, table, 1 , 0);
}

void test_hash()
{
	int ret = 0;
	pn_hash_table table;

	pn_hash_table_init(&table, 7 );

	ret = pn_hash_insert( 1 ,  7 , &table );
	assert(ret==0);

	ret = pn_hash_insert( 1 ,  8 , &table );
	printf("%d\n" ,ret );
	assert(ret<0);
}
int main(int argc, char *argv[])
{
	test_hash();
	printf("Hello, world\n");
	
	return 0;
}
