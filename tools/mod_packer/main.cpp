#include <filesystem>
#include <cstdio>
#include <fstream>

#ifndef INSTALLDIR
#error "INSTALLDIR NOT defined"
#endif
#ifndef TARGETDIR
#error "TARGETDIR NOT defined"
#endif
auto InstallDir = std::filesystem::path(INSTALLDIR);

auto filenames = {
#ifdef _WIN32
    "lua51.dll",
    "lua51DS.dll",
    "Winmm.dll",
#endif
};

auto targetDir = std::filesystem::path(TARGETDIR);

int main()
{
    for (auto filename : filenames)
    {
        auto path = InstallDir / filename;
        auto path_cstr = path.string();
        if (!std::filesystem::exists(path))
        {
            fprintf(stderr, "can't find %s", path_cstr.c_str());
            return -1;
        }
        auto fp = fopen(path_cstr.c_str(), "rb");
        uint8_t buf[4096];
        std::string filecontext;
        static_assert(sizeof(uint8_t) == sizeof(char));
        for (;;)
        {
            auto len = fread(buf, sizeof(uint8_t), sizeof(buf), fp);
            if (feof(fp))
            {
                break;
            }
            if (ferror(fp))
            {
                fprintf(stderr, "error read file %s", path_cstr.c_str());
                return -2;
            }
            filecontext.append((const char *)buf, len);
        }
        fclose(fp);
        auto targetpath = targetDir / filename;
        targetpath.replace_extension("lua");
        printf("output:%s[%zd]\n", targetpath.string().c_str(), filecontext.size());
        fp = fopen(targetpath.string().c_str(), "w");
        fprintf(fp, "%s", "return \"");
        for (auto c : filecontext)
        {
            fprintf(fp, "\\%03hhu", (uint8_t)c);
        }
        fprintf(fp, "%s", "\"");
        fclose(fp);
    }
    return 0;
}