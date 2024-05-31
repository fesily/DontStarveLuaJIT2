#include <zip.h>
#include <memory>
#include <string>
#include <string_view>
#include <filesystem>
#include <format>
#include <unordered_map>
#include "zipfile.hpp"
#include <sstream>

using namespace std::literals;

struct memory_file final : public file_interface {
    std::istringstream ss;

    memory_file(std::istringstream s) : ss{std::move(s)} {
    }

    ~memory_file() override {
    }

    int fclose() override {
        ss = {};
        return 0;
    }

    size_t fread(void *buf, size_t element_size, size_t count) override {
        return ss.readsome((char *) buf, element_size * count);
    }

    int error_code = 0;

    size_t fwrite(void const *buf, size_t element_size, size_t count) override {
        error_code = EPERM;
        return -1;
    }

    int ferror() override {
        return ss.eof() ? 0 : ss.rdstate();
    }

    int fscanf(char const *const _Format, ...) override {
        error_code = EPERM;
        return -1;
    }

    void gets(char *_Str, int _Count) {
        std::ios_base::iostate _State = std::ios_base::goodbit;
        const std::istream::sentry _Ok(ss, true);
        auto _Delim = '\n';
        auto _Chcount = 0;
        using _Traits = std::char_traits<char>;

        if (_Ok && 0 < _Count) { // state okay, extract characters
            try {

                auto _Meta = ss.rdbuf()->sgetc();

                for (; 0 < --_Count; _Meta = ss.rdbuf()->snextc()) {
                    if (_Traits::eq_int_type(_Traits::eof(), _Meta)) { // end of file, quit
                        _State |= std::ios_base::eofbit;
                        break;
                    } else { // got a character, add it to string
                        *_Str++ = _Traits::to_char_type(_Meta);
                        _Chcount++;
                        if (_Traits::to_char_type(_Meta) == _Delim) {
                            ss.rdbuf()->snextc();
                            break;
                        }
                    }
                }
            }
            catch (...) {
                ss.setstate(std::ios_base::badbit);
            }
        }

        ss.setstate(_Chcount == 0 ? _State | std::ios_base::failbit : _State);
        *_Str = char(); // add terminating null character
    }

    char *fgets(char *_Str, int _Count) override {
        gets(_Str, _Count);
        return ss ? _Str : nullptr;
    }

    int fseeko(off_t _Offset, int _Origin) override {
        ss.seekg(_Offset, (std::ios_base::seekdir) _Origin);
        return ss ? 0 : -1;
    }

    off_t ftello() override {
        return ss.tellg();
    }

    void clearerr() override {
        ss.clear();
    }
};

struct zip_manager : public zip_manager_interface {
    std::string prefix;
    zip_t *archive = nullptr;
    std::unordered_map<std::string, zip_int64_t> paths;

    zip_manager(std::filesystem::path p) {
        prefix = p.stem().string() + "/";
        archive = zip_open(p.string().c_str(), 0, nullptr);
        auto len = zip_get_num_entries(archive, 0);
        for (zip_int64_t i = 0; i < len; i++) {
            auto name = zip_get_name(archive, i, 0);
            paths[name] = i;
        }
    }

    std::expected<std::string, std::string_view> readfile(const std::filesystem::path &path) override {
        const auto key = path.string();
        if (!paths.contains(key)) {
            return std::unexpected("can't find file"sv);
        }

        std::unique_ptr<zip_file_t, void (*)(zip_file_t *)> fp(zip_fopen_index(archive, paths[key], 0),
                                                               [](zip_file_t *p) { if (p) zip_fclose(p); });
        if (fp == nullptr) {
            return std::unexpected("can't find file"sv);
        }
        std::string res;
        while (true) {
            char buf[4096];
            int readed = zip_fread(fp.get(), buf, sizeof(buf));
            if (readed > 0) {
                res.append(buf, readed);
            } else if (readed == 0) {
                break;
            } else {
                return std::unexpected("read file error"sv);
            }
        }
        return res;
    }

    zip_file_interface *fopen(const std::filesystem::path &p) override {
        auto res = readfile(p);
        if (!res) {
            return nullptr;
        }
        return new memory_file(std::istringstream(res.value()));
    }

    ~zip_manager() {
        if (archive)
            zip_close(archive);
    }
};

std::unique_ptr<zip_manager_interface> create_zip_manager(std::filesystem::path zip_path) {
    return std::make_unique<zip_manager>(std::move(zip_path));
}