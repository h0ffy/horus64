#include "libc.h"


extern int * find_kernelwin32();
extern int find_functionwin32(unsigned int *kernel_base, int api_hash);

extern int * find_kernelwin64();
extern int find_functionwin64(unsigned long *kernel_base, int api_hash);

