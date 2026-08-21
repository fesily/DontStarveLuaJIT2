#pragma once

namespace ds::shadow {

// Gum-replace Shadow DCR + CacheWorld only. Flush after original Shadow DCR.
// Healthy = GenerateVB + BindProgram pin + sil.ksh. No AnimDraw / Unbind / gl*.
// LoadSilShader may defer to first Shadow DCR.

bool InstallSilhouetteHooks();

} // namespace ds::shadow
