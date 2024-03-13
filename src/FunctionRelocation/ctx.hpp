#pragma once

#include <cstdint>
namespace function_relocation {
	struct Ctx
	{
		uintptr_t hcs;
	};

	bool init_ctx();

	void deinit_ctx();

	Ctx& get_ctx();

}