#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"

size_t log_info_buf(const char *buf, size_t len)
{
	/*
	 * buf could be NULL (not just "").
	 * */
	if (!buf)
		return 0;
	else
		return fwrite(buf, len, 1, f_out);
}

void log_prevalist(int type, const char *fmt, va_list args)
{
    char *buf1, *buf2;
    int len;
       
	len = vasprintf(&buf1, fmt, args);
    if (len < 0)
        return;
    len = asprintf(&buf2, "%-8s %s", debug_levels[type].name, buf1);
    free(buf1);
    if (len < 0)
        return;
    log_info_buf(buf2, len);
    free(buf2);
}


void __dprint(int type, const char *str, ...)
{
	va_list args;
	assert(type < FDPFS_DEBUG_MAX);
	va_start(args, str);
	log_prevalist(type, str, args);
	va_end(args);
}
