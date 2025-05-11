#include "Crc32.h"

unsigned int crc32a(char* str) 
{

    unsigned int    byte, mask, crc = 0xFFFFFFFF;
    int             i = 0, j = 0;

    while (str[i] != 0) 
    {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--)
        {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}

unsigned int crc32w(wchar_t* wstr) 
{
    unsigned int byte, mask, crc = 0xFFFFFFFF;
    int i = 0, j = 0;
    unsigned char* bytes = (unsigned char*)wstr;

    while (bytes[i] != 0 || bytes[i + 1] != 0) {
        byte = bytes[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;

        byte = bytes[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }

    return ~crc;
}

