/* inc/acconfig.h.  Generated from acconfig.h.in by configure.  */
/* inc/acconfig.h.in.  Generated from configure.ac by autoheader.  */

/* align each field of dbHeader class on its page boudary */
/* #undef ALIGN_HEADER */

/* define autoincrement fileds support */
#define AUTOINCREMENT_SUPPORT 1

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* define diskless mode operations (database not persistent) */
/* #undef DISKLESS_CONFIGURATION */

/* disable OID reuse within the same session */
/* #undef DO_NOT_REUSE_OID_WITHIN_SESSION */

/* no checks and no messages */
#define FASTDB_DEBUG DEBUG_TRACE_IMPORTANT

/* define to use a separate thread for committing DB changes) */
/* #undef FUZZY_CHECKPOINT */

/* call dbDatabase::handleError instead of assert() */
#define HANDLE_ASSERTION_FAILURES 1

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* define whether to use clock_gettime() */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* Define to 1 if you have the `gethostbyname_r' function. */
#define HAVE_GETHOSTBYNAME_R 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `m' library (-lm). */
#define HAVE_LIBM 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `munmap' function. */
#define HAVE_MUNMAP 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the `pow' function. */
#define HAVE_POW 1

/* Define to 1 if the system has the type `ptrdiff_t'. */
#define HAVE_PTRDIFF_T 1

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Define to 1 if you have the `regcomp' function. */
#define HAVE_REGCOMP 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the `sqrt' function. */
#define HAVE_SQRT 1

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strcoll' function and it is properly defined.
   */
#define HAVE_STRCOLL 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* carry on all string comparisons as case insensitive */
/* #undef IGNORE_CASE */

/* define not to flush DB on commit (not fault tolerant!) */
/* #undef NO_FLUSH_ON_COMMIT */

/* define not to use mmap */
/* #undef NO_MMAP */

/* indicates that pthread lib isn't required */
/* #undef NO_PTHREADS */

/* Name of package */
#define PACKAGE "fastdb"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "knizhnik@garret.ru"

/* Define to the full name of this package. */
#define PACKAGE_NAME "fastdb"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "fastdb 3.53"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "fastdb"

/* Define to the version of this package. */
#define PACKAGE_VERSION "3.58"

/* keep compatibility with DB version 3.17-3.38 */
/* #undef PAD_HEADER */

/* define to use mprotect() to prevent accidantal DB corruption) */
/* #undef PROTECT_DATABASE */

/* define to release critical sections on process crash) */
/* #undef RECOVERABLE_CRITICAL_SECTION */

/* specify rectangle area type (db_int8|double|...) */
#define RECTANGLE_AREA_TYPE db_int8

/* specify rectangle coordinate type (int|double|...) */
#define RECTANGLE_COORDINATE_TYPE int

/* specify rectangle dimension */
#define RECTANGLE_DIMENSION 2

/* indicates that replication support is enabled */
/* #undef REPLICATION_SUPPORT */

/* enable support for authentication */
/* #undef SECURE_SERVER */

/* define to use the SO_LINGER option) */
/* #undef SOCK_LINGER */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* define to wait ACK from all slave nodes on commit) */
/* #undef SYNCHRONOUS_REPLICATION */

/* enable throwing C++ exceptions on error */
#define THROW_EXCEPTION_ON_ERROR 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* use Doug Lea version of malloc */
/* #undef USE_DLMALLOC */

/* defines whether to use C locale for string comparison operations */
#define USE_LOCALE_SETTINGS 1

/* indicates that fastdb classes must be places in seperate namespaces */
/* #undef USE_NAMESPACES */

/* define to use shmem for DB and monitor */
/* #undef USE_POSIX_MMAP */

/* define to use POSIX sempahores instead of SysV ones */
/* #undef USE_POSIX_SEMPAHORES */

/* enable support for internal http server queue manager */
/* #undef USE_QUEUE_MANAGER */

/* indicates to use regex library */
/* #undef USE_REGEX */

/* enable support for STL strings */
#define USE_STD_STRING 1

/* Version number of package */
#define VERSION "3.53"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* define database offset bit size */
#define dbDatabaseOffsetBits 32

/* define database OID bit size */
#define dbDatabaseOidBits 32

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */
