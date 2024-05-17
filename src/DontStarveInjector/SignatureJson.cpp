#include <charconv>
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>

#include <nlohmann/json.hpp>

#include "SignatureJson.hpp"
#include "GameVersionFile.hpp"

using namespace std::literals;

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Signatures, version, funcs);

static std::string get_signatures_filename(bool isClient) {
    return "signatures_"s + (isClient ? "client" : "server") + ".json";
}

const char *SignatureJson::version_path = "../version.txt";

intptr_t SignatureJson::current_version() {
    static auto v = readGameVersion(version_path);
    return v;
}

std::optional<Signatures> SignatureJson::read_from_signatures() {
    std::ifstream sf(get_signatures_filename(isClient));
    if (!sf.is_open())
        return std::nullopt;
    nlohmann::json j;
    sf >> j;
    return j.get<Signatures>();
}

void SignatureJson::update_signatures(const Signatures &signatures) {
    assert(current_version() == signatures.version);
    std::ofstream sf(get_signatures_filename(isClient));
    nlohmann::json j;
    nlohmann::to_json(j, signatures);
    sf << j;
}
