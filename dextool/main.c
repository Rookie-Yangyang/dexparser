#include <stdio.h>
#include <errno.h>

#include "dexparse.c"
#include "dexparse.h"

int main()
{
	FILE*            fp;
	size_t           size;
	void*            dex = NULL;
	unsigned char*   buf = NULL;
	
	fp = fopen("classes.dex", "rb");//打开dex文件
	if (fp == NULL)
	{
		printf("ERR:open file failure %s\n",strerror(errno));
		return -1;
	}
	
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	//printf("size is %zd\n",size);
	fseek(fp, 0, SEEK_SET);

	buf = (unsigned char *)malloc(size);
	if (NULL == buf)
	{
		printf("ERR:buf malloc failure %s\n",strerror(errno));
		fclose(fp);
		return -1;
	}
	
	if (fread(buf, 1, size, fp) != size)
	{
		printf("Err: read file %s failed.\n", strerror(errno));
		free(buf);
		fclose(fp);
		return -1;
	}

	//printf("read file buf is；%s\n",buf);

	dex = DexOpen(buf, size);
	if (dex == NULL)
	{
	    printf("DexOpen filure!\n");
		free(buf);
		fclose(fp);
		return -1;
	}
	
	print_Header(dex);
	//print_String(dex);
	//print_Typelist(dex);
	//print_Protolist(dex);
	//print_Methodlist(dex);
	//print_Fieldslist(dex);
	//print_Classname(dex);
	
	DexClose(dex);

	free(buf);
	fclose(fp);

	return 0;
}
