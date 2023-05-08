#include <stdio.h>
#include <stdarg.h>

#include "util.h"

void report(char indicator, int level, const char *fmt, ...) 
{
    FILE *stream = (level == ERROR_LEVEL) ? stderr : stdout;
    va_list a;

    if (level > LOG_LEVEL)
        return;

    va_start(a, fmt);
    fprintf(stream, "[%c] %s", indicator, (level == ERROR_LEVEL) ? "ERROR: " : "");
    vfprintf(stream, fmt, a);
    va_end(a);
}