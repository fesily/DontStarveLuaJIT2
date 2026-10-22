#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <string>
#include <vector>

#include "options.h"
#include "log.h"

#define ERROUT stderr

static thread_local std::string g_last_error;

void
nucleus_clear_last_error(void)
{
  g_last_error.clear();
}

const char *
nucleus_last_error(void)
{
  return g_last_error.c_str();
}


void
verbose(int level, char const *fmt, ...)
{
  va_list args;

  if(options.verbosity >= level) {
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
  }
}


void
print_warn(char const *fmt, ...)
{
  va_list args;

  if(options.warnings) {
    va_start(args, fmt);
    fprintf(ERROUT, "WARNING: ");
    vfprintf(ERROUT, fmt, args);
    fprintf(ERROUT, "\n");
    va_end(args);
  }
}


void
print_err(char const *fmt, ...)
{
  va_list args;
  char stackbuf[512];

  va_start(args, fmt);
  fprintf(ERROUT, "ERROR: ");
  vfprintf(ERROUT, fmt, args);
  fprintf(ERROUT, "\n");
  va_end(args);

  va_start(args, fmt);
  int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, args);
  va_end(args);
  if(n <= 0) {
    g_last_error = fmt;
  } else if((size_t)n < sizeof(stackbuf)) {
    g_last_error.assign(stackbuf, (size_t)n);
  } else {
    std::vector<char> heap((size_t)n + 1);
    va_start(args, fmt);
    vsnprintf(heap.data(), heap.size(), fmt, args);
    va_end(args);
    g_last_error.assign(heap.data(), (size_t)n);
  }
}

