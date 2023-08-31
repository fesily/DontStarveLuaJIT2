#pragma once
#include "frida-gum.h"
#include <string>
#include <functional>
struct MemorySignature
{
	const char *pattern;
	int pattern_offset;
	int page = GUM_PAGE_EXECUTE;
	GumAddress target_address = 0;
	GumMatchPattern *match_pattern;

	MemorySignature(const char *p, int offset) : pattern{p}, pattern_offset{offset} {}
	GumAddress scan(const char *m);
};
using in_function_t = std::function<bool(void*)>;
std::string create_signature(void *func, void *module_base, const in_function_t& in_func);
void *fix_func_address_by_signature(void *target, void *module_base, void *original, void *original_module_base, const in_function_t &in_func);