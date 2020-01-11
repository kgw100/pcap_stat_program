#pragma once

#include <unistd.h>
#include <stdint.h>
#include <string>
//#pragma pack (1);


void usage();
void tohex(const u_char * in, size_t insz, char * out, size_t outsz);
