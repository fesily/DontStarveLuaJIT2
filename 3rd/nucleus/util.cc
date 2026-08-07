#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <random>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#include <libgen.h>
#endif

#include "util.h"

/*******************************************************************************
 **                                string utils                               **
 ******************************************************************************/
std::string
str_realpath(std::string s)
{
#if defined(_WIN32)
  char real[MAX_PATH + 1];
  DWORD n = GetFullPathNameA(s.c_str(), MAX_PATH, real, NULL);
  if (n == 0 || n >= MAX_PATH) {
    return "";
  }
  return std::string(real);
#else
  char real[PATH_MAX+1];

  if(!realpath(s.c_str(), real)) {
    return "";
  }
  return std::string(real);
#endif
}


std::string
str_realpath_dir(std::string s)
{
  std::string full = str_realpath(s);
  if (full.empty()) {
    return "";
  }
#if defined(_WIN32)
  size_t pos = full.find_last_of("\\/");
  if (pos == std::string::npos) {
    return ".";
  }
  if (pos == 0) {
    return full.substr(0, 1);
  }
  return full.substr(0, pos);
#else
  char real[PATH_MAX+1], *dir;
  strncpy(real, full.c_str(), PATH_MAX);
  real[PATH_MAX] = '\0';
  dir = dirname(real);
  return std::string(dir);
#endif
}


std::string
str_realpath_base(std::string s)
{
  std::string full = str_realpath(s);
  if (full.empty()) {
    return "";
  }
#if defined(_WIN32)
  size_t pos = full.find_last_of("\\/");
  if (pos == std::string::npos) {
    return full;
  }
  return full.substr(pos + 1);
#else
  char real[PATH_MAX+1], *base;
  strncpy(real, full.c_str(), PATH_MAX);
  real[PATH_MAX] = '\0';
  base = basename(real);
  return std::string(base);
#endif
}


std::string
str_getenv(std::string env)
{
  char *e;

  e = getenv(env.c_str());
  return e ? std::string(e) : "";
}

/*******************************************************************************
 **                               rand functions                              **
 ******************************************************************************/
uint64_t
rand64()
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<unsigned long long> dis(0, 0xffffffffffffffffULL);
  return dis(gen);
}


uint64_t
xorshift128plus()
{
  uint64_t x, y;
  static uint64_t s[2];
  static int inited = 0;

  /* Upstream seeds from rand64() (random_device). Keep that on all hosts;
   * fixed constants were a temporary portability stand-in and are not retained. */
  if (!inited) {
    s[0] = rand64();
    s[1] = rand64();
    inited = 1;
  }

  x = s[0];
  y = s[1];

  s[0] = y;
  x ^= x << 23;
  s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);

  return s[1] + y;
}


uint64_t
fast_rand64()
{
  return xorshift128plus();
}
