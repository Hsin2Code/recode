#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include "journal.h"

void _log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    FILE * pf = fopen(EDP_LOG, "a+");
    if(NULL == pf) {
        printf("open log file failed...:%s.\n",strerror(errno));
    }
    char buf[1024] = {0};
    vsnprintf(buf, sizeof(buf), fmt, ap);
    /* 获取系统时间 */
    time_t timep;
    time(&timep);
    /* 写入日志文件 */
    fprintf(pf, "Time\t: %s%s", ctime(&timep),buf);
    fclose(pf);

    va_end(ap);
}
