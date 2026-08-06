#pragma once

#include <cstdint>
#include <atomic>
#include "export.hpp"
namespace function_relocation {
	struct Ctx
	{
		uintptr_t hcs;
        std::atomic_int16_t ref = 0;
	};

	FUNCTION_RELOCATION_API bool init_ctx();

	FUNCTION_RELOCATION_API void deinit_ctx();

	FUNCTION_RELOCATION_API Ctx& get_ctx();

}
