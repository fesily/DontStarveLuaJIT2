include(CMakeFindDependencyMacro)
find_dependency(ZLIB)
if(@ANGLE_PACKAGE_USE_VULKAN@)
	find_dependency(Vulkan)
	find_dependency(SPIRV-Tools CONFIG)
	find_dependency(VulkanMemoryAllocator CONFIG)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/unofficial-angle-targets.cmake")
