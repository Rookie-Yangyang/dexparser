#ifndef DEXPARSE_H
#define DEXPARSE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define DEX_MAGIC "dex\n035\0"

//文件头的结构体
typedef struct{
	uint8_t         magic[8];//魔数
	uint32_t        checksum;//校验和
	uint8_t         signature[20];//SHA-1签名信息
	uint32_t        file_size;//文件大小
	uint32_t        header_size;//文件头大小
	uint32_t        endianTag;//字节序标志
	uint32_t        link_size;//链接段大小
	uint32_t        link_off;//链接段的偏移量
	uint32_t        map_off;//maplist的偏移
	uint32_t        stringids_size;
	uint32_t        stringids_off;
	uint32_t        typeids_size;
	uint32_t        typeids_off;
	uint32_t        protoids_size;
	uint32_t        protoids_off;
	uint32_t        fieldids_size;
	uint32_t        fieldids_off;
	uint32_t        methodids_size;
	uint32_t        methodids_off;
	uint32_t        classdefs_size;
	uint32_t        classdefs_off;
	uint32_t        data_size;
	uint32_t        data_off;
}DexHeader;

//string的数据结构
typedef struct{
	uint32_t      stringDataoff;//字符串表的地址索引
}stringids_item;

//typeid的数据结构
typedef struct{
	uint32_t      descriptor_index;
}typeids_item;

typedef struct{
	uint32_t	size;
	typeids_item	list[1];
}typelist_item;

typedef struct{
	uint32_t      shortyIdx;
	uint32_t      returnTypeIdx;
	uint32_t      parametersoff;
}protoids_item;

typedef struct{
	uint16_t      class_idx;
	uint16_t      type_idx;
	uint32_t      name_idx;
}fieldids_item;

typedef struct{
	uint16_t      class_idx;
	uint16_t      proto_idx;
	uint32_t      name_idx;
}methodids_item;

typedef struct{
	uint32_t      class_idx;
	uint32_t      access_flags;
	uint32_t      superclass_idx;
	uint32_t      intrfaces_off;
	uint32_t      sourcefile_idx;
	uint32_t      annotations_off;
	uint32_t      classsdata_off;
	uint32_t      staticvalue_off;
}classdefs_item;

typedef struct {
	uint8_t		bleargh;
}link_item;

typedef struct{
	unsigned char               *data;
	size_t                      len;
	
	DexHeader            *header;
	stringids_item       *string;
	typeids_item         *type;
	protoids_item        *proto;
	fieldids_item        *field;
	methodids_item       *method;
	classdefs_item       *classdef;
	link_item            *link;
}DexFile;

void *DexOpen(unsigned char *buf, size_t size);

void DexClose(void *dexfile);

char *getString(DexFile *dex, uint32_t index);

char *getType(DexFile* dex, uint32_t index);

char *getProtoshorty(DexFile* dex, uint32_t index);

char *getProtoreturntype(DexFile* dex, uint32_t index);

uint32_t getProtoparacount(DexFile* dex, uint32_t index);

char *getProtoparameter(DexFile* dex, uint32_t index, uint32_t n);

char *getFieldclass(DexFile* dex, uint32_t index);

char *getFieldtype(DexFile* dex, uint32_t index);

char *getFieldname(DexFile* dex, uint32_t index);

char *getMethodname(DexFile* dex, uint32_t index);

char *getMethodclass(DexFile* dex, uint32_t index);

uint32_t getMethodprotoid(DexFile* dex, uint32_t index);

char *getClassname(DexFile* dex, uint32_t index);

void print_Header(void *dexfile);

void print_String(void *dexfile);

void print_Typelist(void *dexfile);

void print_Protolist(void *dexfile);

void print_Methodlist(void *dexfile);

void print_Fieldslist(void *dexfile);

void print_Classname(void *dexfile);

#endif
