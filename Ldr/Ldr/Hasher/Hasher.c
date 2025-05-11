#include <stdio.h>
#include "Crc32.h"

int main()
{
	printf("Hash Ansi	0x%0.8X\n",	HASHa("Hello"));
	printf("Hash Unicode	0x%0.8X\n", HASHw(L"World"));
}