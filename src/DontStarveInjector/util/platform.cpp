#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

std::filesystem::path getExePath()
{
        static std::filesystem::path p = []
        {
#ifdef _WIN32
                char path[MAX_PATH];
                GetModuleFileNameA(NULL, path, 255);
#else
                char path[1024];
                ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
                path[len == -1 ? 0 : len] = 0;
#endif
                return std::filesystem::path{path};
        }();
        return p;
}

module_handler_t loadlib(const char *name)
{
        if (auto p = getExePath() / name; std::filesystem::exists(p))
                return loadlib(p.c_str());
        if (auto p = std::filesystem::current_path() / name; std::filesystem::exists(p))
                return loadlib(p.c_str());
        return
#ifdef _WIN32
            LoadLibraryA(name);
#else
            dlopen(name, RTLD_NOW);
#endif
}

void *loadlibproc(module_handler_t h, const char *name)
{
        return
#ifdef _WIN32
            GetProcAddress
#else
            dlsym
#endif
            (h, name);
}

void unloadlib(module_handler_t h)
{
#ifdef _WIN32
        FreeLibrary(h);
#else
        dlclose(h);
#endif
}

#include <frida-gum.h>
#ifndef _WIN32
#include <gumlinux-priv.h>

static gboolean
gum_memory_get_protection(gconstpointer address,
                          gsize n,
                          gsize *size,
                          GumPageProtection *prot)
{
        gboolean success;
        GumProcMapsIter iter;
        const gchar *line;

        if (size == NULL || prot == NULL)
        {
                gsize ignored_size;
                GumPageProtection ignored_prot;

                return gum_memory_get_protection(address, n,
                                                 (size != NULL) ? size : &ignored_size,
                                                 (prot != NULL) ? prot : &ignored_prot);
        }

        if (n > 1)
        {
                gsize page_size, start_page, end_page, cur_page;

                page_size = gum_query_page_size();

                start_page = GPOINTER_TO_SIZE(address) & ~(page_size - 1);
                end_page = (GPOINTER_TO_SIZE(address) + n - 1) & ~(page_size - 1);

                success = gum_memory_get_protection(GSIZE_TO_POINTER(start_page), 1, NULL,
                                                    prot);
                if (success)
                {
                        *size = page_size - (GPOINTER_TO_SIZE(address) - start_page);
                        for (cur_page = start_page + page_size;
                             cur_page != end_page + page_size;
                             cur_page += page_size)
                        {
                                GumPageProtection cur_prot;

                                if (gum_memory_get_protection(GSIZE_TO_POINTER(cur_page), 1, NULL,
                                                              &cur_prot) &&
                                    (cur_prot != GUM_PAGE_NO_ACCESS ||
                                     *prot == GUM_PAGE_NO_ACCESS))
                                {
                                        *size += page_size;
                                        *prot &= cur_prot;
                                }
                                else
                                {
                                        break;
                                }
                        }
                        *size = MIN(*size, n);
                }

                return success;
        }

        success = FALSE;
        *size = 0;
        *prot = GUM_PAGE_NO_ACCESS;

        gum_proc_maps_iter_init_for_self(&iter);

        while (gum_proc_maps_iter_next(&iter, &line))
        {
                gpointer start, end;
                gchar protection[4 + 1];

                sscanf(line, "%p-%p %s ", &start, &end, protection);

                if (start > address)
                        break;
                else if (address >= start && GPOINTER_TO_SIZE(address) + n - 1 < GPOINTER_TO_SIZE(end))
                {
                        success = TRUE;
                        *size = 1;
                        if (protection[0] == 'r')
                                *prot |= GUM_PAGE_READ;
                        if (protection[1] == 'w')
                                *prot |= GUM_PAGE_WRITE;
                        if (protection[2] == 'x')
                                *prot |= GUM_PAGE_EXECUTE;
                        break;
                }
        }

        gum_proc_maps_iter_destroy(&iter);

        return success;
}

#else

static gboolean
gum_memory_get_protection(gconstpointer address,
                          gsize len,
                          GumPageProtection *prot)
{
        gboolean success = FALSE;
        MEMORY_BASIC_INFORMATION mbi;

        if (prot == NULL)
        {
                GumPageProtection ignored_prot;

                return gum_memory_get_protection(address, len, &ignored_prot);
        }

        *prot = GUM_PAGE_NO_ACCESS;

        if (len > 1)
        {
                gsize page_size, start_page, end_page, cur_page;

                page_size = gum_query_page_size();

                start_page = GPOINTER_TO_SIZE(address) & ~(page_size - 1);
                end_page = (GPOINTER_TO_SIZE(address) + len - 1) & ~(page_size - 1);

                success = gum_memory_get_protection(GSIZE_TO_POINTER(start_page), 1,
                                                    prot);

                for (cur_page = start_page + page_size;
                     cur_page != end_page + page_size;
                     cur_page += page_size)
                {
                        GumPageProtection cur_prot;

                        if (gum_memory_get_protection(GSIZE_TO_POINTER(cur_page), 1, &cur_prot))
                        {
                                success = TRUE;
                                *prot &= cur_prot;
                        }
                        else
                        {
                                *prot = GUM_PAGE_NO_ACCESS;
                                break;
                        }
                }

                return success;
        }

        success = VirtualQuery(address, &mbi, sizeof(mbi)) != 0;
        if (success)
                *prot = gum_page_protection_from_windows(mbi.Protect);

        return success;
}

#endif

static gboolean
gum_memory_is_execute(gconstpointer address,
                      gsize len)
{
        gsize size;
        GumPageProtection prot;

        if (!gum_memory_get_protection(address, len, &size, &prot))
                return FALSE;
        return size >= len && (prot & GUM_PAGE_EXECUTE) != 0;
}

#ifndef _WIN32
__attribute__((visibility("hidden")))
#endif
bool
memory_is_execute(void *address)
{
        return gum_memory_is_execute(address, 4);
}

#include <fstream>
#include <iostream>
#include <string>
const char *get_cwd()
{
#ifdef _WIN32
        return GetCommandLineA();
#else
        static auto cmd = []()
        {
                std::ifstream file("/proc/self/cmdline");
                std::string cmd;
                std::string cmdline;
                while (std::getline(file, cmdline, '\0'))
                {
                        cmd += cmdline + " ";
                }
                cmd.pop_back();
                return cmd;
        }();
        return cmd.c_str();
#endif
}