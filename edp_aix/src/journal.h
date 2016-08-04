#ifndef _JOURNAL_H_
#define _JOURNAL_H_

#include <errno.h>

#define EDP_LOG "/opt/edp/bin/edp_run.log"

void _log(const char *fmt, ...)__attribute__((format(printf,1,2)));

#define LOG_ERR(fmt,...) _log("[MSG]%s:%d:"fmt"", __FILE__, __LINE__, ##__VA_ARGS__)

#define LOG_MSG(fmt,...) _log("[MSG]%s:%d:"fmt"", __FILE__, __LINE__, ##__VA_ARGS__)

#define LOG_DB(fmt,...) _log("[DB]%s:%d:"fmt"", __FILE__, __LINE__, ##__VA_ARGS__)

#define LOG_RUN(fmt,...) _log("[RUN]%s:%d:"fmt"", __FILE__, __LINE__, ##__VA_ARGS__)

#endif
