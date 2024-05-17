#pragma once

#include <cstdint>
#include <atomic>
namespace function_relocation {
	struct Ctx
	{
		uintptr_t hcs;
        std::atomic_int16_t ref = 0;
	};

	bool init_ctx();

	void deinit_ctx();

	Ctx& get_ctx();

}