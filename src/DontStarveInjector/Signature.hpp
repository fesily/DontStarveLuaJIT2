#pragma once
#include <string>
#include <functional>
#include <stdint.h>
#include <unordered_map>
struct _GumMatchPattern;
typedef struct _GumMatchPattern GumMatchPattern;
struct MemorySignature
{
	const char *pattern;
	int pattern_offset;
	uintptr_t target_address = 0;
	GumMatchPattern *match_pattern;

	MemorySignature(const char *p, int offset) : pattern{p}, pattern_offset{offset} {}
	uintptr_t scan(const char *m);
};
struct Signatures {
	uintptr_t version;
	std::unordered_map<std::string, uintptr_t> funcs;
};

using in_function_t = std::function<bool(void*)>;
std::string create_signature(void *func, void *module_base, const in_function_t& in_func);
void *fix_func_address_by_signature(void *target, void *module_base, void *original, void *original_module_base, const in_function_t &in_func);