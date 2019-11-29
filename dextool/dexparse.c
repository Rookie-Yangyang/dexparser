#include <stdio.h>

#include "dexparse.h"



//比较文件头信息
void *DexOpen(unsigned char *buf, size_t size)
{
	//printf("buf is %s, size = %zd\n",buf,size);
	DexFile*           dex = NULL;
	//printf("DexOpen\n");
	
	if (NULL == buf || size == 0)
	{
		printf("buf or size is NULL\n");
		return NULL;
	}

	//printf("buf is %s, size = %zd\n",buf,size);
	
	dex = (DexFile*)malloc(sizeof(DexFile));
	if (dex == NULL)
	{
		printf("dex malloc filure\n");
		return NULL;
	}
		
	dex->data = buf;
	dex->len = size;
	
	dex->header = (DexHeader*)dex->data;

	//printf("dex->len=%zd\n",dex->len);
	//printf("dex->data=%s\n",dex->data);
	//printf("dex->header->file_size=%d\n",dex->header->file_size);
	//printf("DexFile is %ld\n",sizeof(DexFile));
	
	if ((dex->len < sizeof(DexFile)) || (dex->len != dex->header->file_size))
	{
		//大小不等，退出
		printf("DexFile is %ld\n",sizeof(DexFile));
		free(dex);
		return NULL;
	}

	//printf("dex->header->magic=%s\n",dex->header->magic);
	if (memcmp(dex->header->magic, DEX_MAGIC, 8) != 0)
	{
		//魔数不等，退出
		printf("magic is not equal!\n");
		free(dex);
		return NULL;
	}

	//printf("dex->header->checksum is 0x%02x\n",dex->header->checksum);
	/*if(Adler32Checksum(dex->data+8, dex->len-8) != dex->header->checksum)
	{
		//校验和
		printf("dex->header->checksum is 0x%02x\n",dex->header->checksum);
		free(dex);
		return NULL;
	}*/
	
	dex->string = (stringids_item*)(dex->data + dex->header->stringids_off);
	dex->type = (typeids_item*)(dex->data + dex->header->typeids_off);
	dex->proto = (protoids_item*)(dex->data + dex->header->protoids_off);
	dex->field = (fieldids_item*)(dex->data + dex->header->fieldids_off);
	dex->method = (methodids_item*)(dex->data + dex->header->methodids_off);
	dex->classdef = (classdefs_item*)(dex->data + dex->header->classdefs_off);
	dex->link = (link_item*)(dex->data + dex->header->link_off);
	
	return dex;
}

//释放dex
void DexClose(void *dexfile)
{
	DexFile*                     dex = (DexFile*)dexfile;
	
	free(dex);
}

//获取字符串
char *getString(DexFile *dex, uint32_t index)
{
	stringids_item*            idx;
	unsigned char*             p;
	
	if (index >= dex->header->stringids_size)
		return NULL;
	
	idx =(stringids_item*) dex->string + index;
	if (idx->stringDataoff >= dex->len)
		return NULL;
	
	p = dex->data + idx->stringDataoff;//指向字符串列表
	
	while(*(p++) > 0x7f)
		;
	return (char*)p;
}

//获取类型
char *getType(DexFile* dex, uint32_t index)
{
	typeids_item*        idx;
	
	if (index >= dex->header->typeids_size)
		return NULL;
	
	idx = (typeids_item*)dex->type + index;
	
	return getString(dex, idx->descriptor_index);
}

//方法字符串
char *getProtoshorty(DexFile* dex, uint32_t index)
{
	protoids_item*            idx;
	
	if (index >= dex->header->protoids_size)
		return NULL;
	
	idx = (protoids_item*)dex->proto + index;
	
	return getString(dex, idx->shortyIdx);
}

//返回值类型
char *getProtoreturntype(DexFile* dex, uint32_t index)
{
	protoids_item*          idx;
	
	if (index >= dex->header->protoids_size)
		return NULL;
	
	idx = (protoids_item*)dex->proto + index;
	
	return getType(dex, idx->returnTypeIdx);
}

//参数个数，失败返回负数，成功返回参数个数
uint32_t getProtoparacount(DexFile* dex, uint32_t index)
{
	protoids_item*            idx;
	typelist_item*            para;
	
	if (index >= dex->header->protoids_size)
		return -1;
	
	idx = (protoids_item*)dex->proto + index;
	if (idx->parametersoff >= dex->len)
		return -1;
	
	if (idx->parametersoff == 0)
		return 0;
	
	para = (typelist_item*)(dex->data + idx->parametersoff);//指向参数列表
	
	return para->size;
}

//获取参数类型
char *getProtoparameter(DexFile* dex, uint32_t index, uint32_t n)
{
	protoids_item*            idx;
	typelist_item*            para;

	if (index >= dex->header->protoids_size)
		return NULL;
	
	idx = (protoids_item*)dex->proto + index;
	if (idx->parametersoff >= dex->len)
		return NULL;
	if (idx->parametersoff == 0)
		return NULL;
	
	para = (typelist_item*)(dex->data + idx->parametersoff);
	
	return getType(dex, para->list[n].descriptor_index);
}

//获取fields_id所属的class的类型
char *getFieldclass(DexFile* dex, uint32_t index)
{
	fieldids_item*               idx;
	
	if (index >= dex->header->fieldids_size)
		return NULL;
	
	idx = (fieldids_item*)dex->field + index;
	
	return getType(dex, idx->class_idx);
}


//获取fields_idS的类型
char *getFieldtype(DexFile* dex, uint32_t index)
{
	fieldids_item*               idx;
	
	if (index >= dex->header->fieldids_size)
		return NULL;
	
	idx = (fieldids_item*)dex->field + index;
	
	return getType(dex, idx->type_idx);
}

//获取fields_ids的名称
char *getFieldname(DexFile* dex, uint32_t index)
{
	fieldids_item*               idx;
	
	if (index >= dex->header->fieldids_size)
		return NULL;
	
	idx = (fieldids_item*)dex->field + index;
	
	return getString(dex, idx->name_idx);
}

//获取method_ids的名称
char *getMethodname(DexFile* dex, uint32_t index)
{
	methodids_item*             idx;
	
	if (index >= dex->header->methodids_size)
		return NULL;
	
	idx = (methodids_item*)dex->method + index;
	
	return getString(dex, idx->name_idx);
}

//获取method_ids的class
char *getMethodclass(DexFile* dex, uint32_t index)
{
	methodids_item*             idx;
	
	if (index >= dex->header->methodids_size)
		return NULL;
	
	idx = (methodids_item*)dex->method + index;
	
	return getType(dex, idx->class_idx);
}

//获取method_ids的protoid
uint32_t getMethodprotoid(DexFile* dex, uint32_t index)
{
	methodids_item*             idx;
	
	if (index >= dex->header->methodids_size)
		return -1;
	
	idx = (methodids_item*)dex->method + index;
	
	return idx->proto_idx;
}

char *getClassname(DexFile* dex, uint32_t index)
{
		classdefs_item*           def;

		if (index >= dex->header->classdefs_size)
				return NULL;

		def = (classdefs_item*)dex->classdef + index;

		return getType(dex, def->class_idx);
}

//打印头部信息
void print_Header(void *dexfile)
{
	DexFile*             dex = (DexFile*)dexfile;
	
	printf("struct header {\n");
	//printf("\tmagic[8]: %s\n", dex->header->magic);
	printf("\tmagic[8]: %3.3s ", dex->header->magic);
	printf("%s\n", dex->header->magic + 4);
	printf("\tchecksum: %x\n", dex->header->checksum);
	
	printf("\tsignature[20]: ");
	for (int i=0;i < 20; i++)
	{
		printf("%x", dex->header->signature[i]);

	}
	printf("\n");

	printf("\tfile_size: %d\n", dex->header->file_size);
	printf("\theader_size: %d\n", dex->header->header_size);
	printf("\tendianTag: %x\n", dex->header->endianTag);
	printf("\tlink_size: %d\n", dex->header->link_size);
	printf("\tlink_off: %d\n", dex->header->link_off);
	printf("\tmap_off: %d\n",dex->header->map_off);
	printf("\tstringids_size: %d\n",dex->header->stringids_size);
	printf("\tstringids_off: %d\n",dex->header->stringids_off);
	printf("\ttypeids_size: %d\n",dex->header->typeids_size);
	printf("\ttypeids_off: %d\n",dex->header->typeids_off);
	printf("\tprotoids_size: %d\n",dex->header->protoids_size);
	printf("\tprotoids_off: %d\n",dex->header->protoids_off);
	printf("\tfieldids_size: %d\n",dex->header->fieldids_size);
	printf("\tfieldids_off: %d\n",dex->header->fieldids_off);
	printf("\tmethodids_size: %d\n",dex->header->methodids_size);
	printf("\tmethodids_off: %d\n",dex->header->methodids_off);
	printf("\tclassdefs_size: %d\n",dex->header->classdefs_size);
	printf("\tclassdefs_off: %d\n",dex->header->classdefs_off);
	printf("\tdata_size: %d\n",dex->header->data_size);
	printf("\tdata_off: %d\n",dex->header->data_off);
	printf("};\n");
}

//打印字符串列表
void print_String(void *dexfile)
{
	DexFile*             dex = (DexFile*)dexfile;
	uint32_t             i;

	for (i=0; i < dex->header->stringids_size; i++)
	{
		printf("string[%u]:%s\n", i, getString(dex, i));
	}
}

//打印类型列表
void print_Typelist(void *dexfile)
{
	DexFile*            dex = (DexFile*)dexfile;
	uint32_t            i;

	for(i=0; i< dex->header->typeids_size; i++)
	{
		printf("type[%u]:%s\n", i, getType(dex, i));
	}
}

//打印proto列表
void print_Protolist(void *dexfile)
{
	DexFile*           dex = (DexFile*)dexfile;
	uint32_t           i, j;

	for (i = 0; i < dex->header->protoids_size; i++)
	{       
		printf("proto[%u]:%s, ret:%s", i, getProtoshorty(dex, i), getProtoreturntype(dex, i));
		for(j = 0; j < getProtoparacount(dex, i); j++)
		{
			printf("para[%u]:%s", j+1, getProtoparameter(dex, i, j));
		}
		printf("\n");
	}
}

//打印fields列表
void print_Fieldslist(void *dexfile)
{
	DexFile*         dex = (DexFile*)dexfile;
	uint32_t         i;

	for (i =0; i < dex->header->fieldids_size; i++)
	{       
		printf("field[%u]:%s -> %s (%s)\n", i, getFieldclass(dex, i), getFieldtype(dex, i), getFieldname(dex, i));
	}
}

//打印方法列表
void print_Methodlist(void *dexfile)
{
	DexFile*         dex = (DexFile*)dexfile;
	uint32_t         i;

	for (i=0; i < dex->header->methodids_size; i++)
	{
		printf("method[%u]:%s -> %s (%s)\n", i, getMethodclass(dex,i), getMethodname(dex, i), getProtoshorty(dex, getMethodprotoid(dex, i)));
	}
}

//打印类名
void print_Classname(void *dexfile)
{
	DexFile*        dex = (DexFile*)dexfile;
	uint32_t        i;

	for(i=0; i < dex->header->classdefs_size; i++)
	{
		printf("class[%u]: %s\n", i, getClassname(dex, i));
	}
}
