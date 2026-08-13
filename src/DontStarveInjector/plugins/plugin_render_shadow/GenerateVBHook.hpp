#pragma once

namespace ds::shadow {

bool InstallGenerateVBHook();
bool IsHookInstalled() noexcept;
void SetSunDriveEnabled(bool on);
void SetLengthBoost(double boost) noexcept;
double GetLengthBoost() noexcept;

} // namespace ds::shadow
