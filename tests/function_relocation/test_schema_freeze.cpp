#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

#define REQUIRE(cond)                                                                           \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            std::cerr << "REQUIRE failed: " << #cond << " (" << __FILE__ << ":"          \
                      << __LINE__ << ")\n";                                                   \
            std::abort();                                                                       \
        }                                                                                       \
    } while (0)

std::filesystem::path signature_header_path() {
    auto source_dir = std::filesystem::path(__FILE__).parent_path();
    return source_dir.parent_path().parent_path() / "src" / "FunctionRelocation" /
        "Signature.hpp";
}

std::string read_file(const std::filesystem::path &path) {
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.is_open());

    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

void test_signature_info_schema_snapshot() {
    const std::string source = read_file(signature_header_path());
    const std::string expected =
        "    struct SignatureInfo {\n"
        "        uintptr_t offset;\n"
        "        std::string pattern;\n"
        "        int pattern_offset;\n"
        "    };\n\n"
        "    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(SignatureInfo, offset, pattern, pattern_offset);\n";

    REQUIRE(source.find(expected) != std::string::npos);
}

}

int main() {
    test_signature_info_schema_snapshot();
    return 0;
}
