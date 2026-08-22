#pragma once

// Dynamic plugins and Injector call gum_*/cs_* via the process-wide shared
// frida-gum library (Frida::Gum). There is no second Gum copy and no Injector
// re-export. This header remains as a documentation include for gum plugins.

// Optional: nothing to #error — missing Frida::Gum fails at CMake/link time.
