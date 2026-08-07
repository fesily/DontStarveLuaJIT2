/* Engineering shim: Nucleus expects <capstone/capstone.h>.
 * This project links Capstone via Frida Gum (single process-wide copy).
 * Include the combined Gum header which embeds the Capstone C API.
 */
#pragma once

#include <frida-gum.h>
