// Shared doctest runner for the C++ test executables.
//
// One TU per test process implements doctest; every other test source only
// includes <doctest/doctest.h> and declares TEST_CASEs. Tests link
// ds_test_doctest (PUBLIC doctest::doctest) instead of carrying their own main.
//
// The main is hand-written rather than DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN so
// that `no-breaks` defaults to true: a failing REQUIRE then unwinds the current
// test case instead of raising a breakpoint that stalls a ctest run whenever a
// debugger is attached. The command line is applied afterwards, so
// `--no-breaks=false` still restores the interactive behaviour.
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

int main(int argc, char** argv) {
    doctest::Context context;
    context.setOption("no-breaks", true);
    context.applyCommandLine(argc, argv);
    return context.run();
}
