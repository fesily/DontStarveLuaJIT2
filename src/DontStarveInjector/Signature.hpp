#pragma once
#include "frida-gum.h"
struct Signature
{
	const char *pattern;
	int pattern_offset;
	int page = GUM_PAGE_EXECUTE;
	GumAddress target_address = 0;
	GumMatchPattern *match_pattern;

	Signature(const char *p, int offset) : pattern{p}, pattern_offset{offset} {}
	GumAddress scan(const char *m);
};
