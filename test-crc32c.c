#include "crc32c.h"

#include <stdio.h>

int
main(int argc, char *argv[])
{
    char test[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    return crc32c(0, test, sizeof(test)) == 0xe3069283 ? 0 : 1;
}
