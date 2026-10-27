#pragma once

#include <optional>
#include <string>

#include "DontStarveSignature.hpp"

struct SignatureJson {
    // On-disk layout version (top-level "format_version"). A document written
    // by any other version — including one without the field — is rejected by
    // read_from_signatures(), so the caller regenerates every entry from
    // scratch instead of trusting entries whose meaning may have changed.
    static constexpr int format_version = 2;

    // Platform section owned by this build, "<system>-<arch>": "windows-x64",
    // "linux-x64", "macos-arm64", … One file may carry every system and
    // architecture: update_signatures() only replaces this section and leaves
    // the others exactly as they were on disk.
    static const char *platform_name();

    // Why read_from_signatures() returned nullopt. create_or_update() uses it to
    // tell "no DB written yet" (Update mode must fail) from "DB from another
    // format version / without this platform's section" (rebuild from scratch).
    enum class ReadStatus {
        Ok,
        Missing,  // the file could not be opened
        Unusable, // unparsable, wrong format_version, or no section for platform_name()
    };

    static intptr_t current_version();

    static const char *version_path;
    bool isClient;
    std::string file_path;
    ReadStatus last_read_status = ReadStatus::Missing;

    // file_path, or <mod>/signatures_{client,server}.json when unset.
    std::string resolved_path() const;

    std::optional<Signatures> read_from_signatures();

    void update_signatures(const Signatures &signatures);
};
