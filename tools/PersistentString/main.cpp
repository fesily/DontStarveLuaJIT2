#include <stdio.h>
#include <PersistentString.hpp>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stdout, "Usage: %s <path_to_persistent_string>\n", argv[0]);
        return 1;
    }

    const char *persistent_string_path = argv[1];
    
    // Here you would typically load and use the persistent string.
    // For demonstration purposes, we will just print the path.
    fprintf(stdout, "Persistent String Path: %s\n", persistent_string_path);
    
    // Add your logic to handle the persistent string here.
    auto context = GetPersistentString(persistent_string_path);
    if (!context) {
        fprintf(stdout, "Failed to get persistent string: %s\n", context.error().c_str());
        return 1;
    }
    fprintf(stdout, "Persistent String Context: %s\n", context->c_str());
    return 0;
}

