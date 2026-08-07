/* Engineering surface: library defaults without CLI getopt.
 * Mirrors the defaults set by parse_options() for non-CLI consumers.
 * Strategy default is "linear" (paper configuration).
 */
#include "options.h"

struct options options;

namespace {

struct NucleusOptionsDefaults {
  NucleusOptionsDefaults() {
    options.verbosity = 0;
    options.warnings = 1;
    options.only_code_sections = 1;
    options.allow_privileged = 0;
    options.summarize_functions = 0;

    options.binary.type = Binary::BIN_TYPE_AUTO;
    options.binary.arch = Binary::ARCH_NONE;
    options.binary.bits = 0;
    options.binary.base_vma = 0;

    options.strategy_function.name = "linear";
    options.strategy_function.score_function = nullptr;
    options.strategy_function.mutate_function = nullptr;
    options.strategy_function.select_function = nullptr;
  }
};

static NucleusOptionsDefaults g_nucleus_options_defaults;

} // namespace
