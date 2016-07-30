#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "type.h"

/* 数据黏贴函数 */
char *
datacat(char *data, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char tmp[LINE_SIZE] = {0};
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    strcat(data, tmp);
    va_end(ap);
    return data;
}
