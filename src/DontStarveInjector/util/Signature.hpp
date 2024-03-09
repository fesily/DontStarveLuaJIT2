#pragma once
#include <string>
#include <functional>
#include <stdint.h>
#include <vector>
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

struct Signature
{
	struct memory_range {
		uintptr_t start;
		size_t len;
	};
	std::vector<std::string> asm_codes;
	std::vector<memory_range> memory_ranges;
	std::string to_string() const;
	bool operator==(const Signature &other) const;
	inline size_t size() const { return asm_codes.size(); }
	inline size_t empty() const { return asm_codes.empty(); }
	const std::string &operator[](size_t index) const { return asm_codes[index]; }
};
bool signature_init();
void signature_deinit();
void init_module_signature(const char* path);
using in_function_t = std::function<bool(void *)>;
Signature create_signature(void *func, const in_function_t &in_func, size_t limit = size_t(-1), bool readRva = true);
void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range = 512, bool updated = true);
void release_signature_cache();