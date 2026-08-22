#pragma once

#include <cstdint>


namespace ds::shadow {

bool InstallGenerateVBHook();
bool IsHookInstalled() noexcept;
uintptr_t GetGenerateVBAddress() noexcept;
void SetSunDriveEnabled(bool on);
void SetEllipseEnabled(bool on) noexcept;
bool IsEllipseEnabled() noexcept;


} // namespace ds::shadow
