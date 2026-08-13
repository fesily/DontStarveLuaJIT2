#pragma once

#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace function_relocation::fixture_loader {

struct FixtureBlob {
  std::string path;
};

struct FixtureCase {
  std::string id;
  std::string title;
  std::string status;
  std::string notes;
  std::vector<FixtureBlob> blobs;
};

struct FixtureManifest {
  int schema_version = 1;
  std::vector<FixtureCase> cases;
};

inline std::string trim(std::string_view text) {
  size_t begin = 0;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
    ++begin;
  }

  size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
    --end;
  }

  return std::string(text.substr(begin, end - begin));
}

inline std::optional<std::pair<std::string, std::string>> split_kv(std::string_view line) {
  const size_t eq = line.find('=');
  if (eq == std::string_view::npos) {
    return std::nullopt;
  }

  auto key = trim(line.substr(0, eq));
  auto value = trim(line.substr(eq + 1));
  if (key.empty()) {
    return std::nullopt;
  }

  return std::make_pair(std::move(key), std::move(value));
}

inline std::vector<std::string> split_csv(std::string_view text) {
  std::vector<std::string> items;
  std::string current;

  for (char ch : text) {
    if (ch == ',') {
      auto item = trim(current);
      if (!item.empty()) {
        items.push_back(std::move(item));
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }

  auto item = trim(current);
  if (!item.empty()) {
    items.push_back(std::move(item));
  }

  return items;
}

inline std::optional<FixtureManifest> load_manifest(const std::filesystem::path &path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    return std::nullopt;
  }

  FixtureManifest manifest;
  FixtureCase *current_case = nullptr;
  std::string line;

  while (std::getline(input, line)) {
    const std::string stripped = trim(line);
    if (stripped.empty() || stripped[0] == '#') {
      continue;
    }

    if (stripped == "[case]") {
      manifest.cases.emplace_back();
      current_case = &manifest.cases.back();
      continue;
    }

    const auto kv = split_kv(stripped);
    if (!kv.has_value()) {
      return std::nullopt;
    }

    const auto &[key, value] = *kv;
    if (key == "schema") {
      try {
        manifest.schema_version = std::stoi(value);
      } catch (...) {
        return std::nullopt;
      }
      continue;
    }

    if (current_case == nullptr) {
      return std::nullopt;
    }

    if (key == "id") {
      current_case->id = value;
    } else if (key == "title") {
      current_case->title = value;
    } else if (key == "status") {
      current_case->status = value;
    } else if (key == "notes") {
      current_case->notes = value;
    } else if (key == "blob") {
      current_case->blobs.push_back(FixtureBlob{value});
    } else if (key == "blobs") {
      for (const auto &blob : split_csv(value)) {
        current_case->blobs.push_back(FixtureBlob{blob});
      }
    } else {
      return std::nullopt;
    }
  }

  return manifest;
}

}
