#include<Windows.h>

#define SEED        0xEDB88870

unsigned int crc32a(char* str);
unsigned int crc32w(wchar_t* wstr);

#define HASHa(API) crc32a((char*)API)
#define HASHw(API) crc32w((wchar_t*)API)