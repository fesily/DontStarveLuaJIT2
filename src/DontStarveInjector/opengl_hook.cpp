#include "APIHook.h"
#include <string>
#include <unordered_map>
#include <vector>

#pragma region OpenGL

typedef void(_stdcall
*PFNGLBINDBUFFERARBPROC)(
int target,
unsigned int buffer
);
typedef void(_stdcall
*PFNGLBUFFERDATAARBPROC)(
int target,
int size,
const void *data,
int usage
);
typedef void(_stdcall
*PFNGLGENBUFFERSARBPROC)(
int n,
unsigned int *buffers
);
typedef void(_stdcall
*PFNGLDELETEBUFFERSARBPROC)(
int n,
const unsigned int *buffers
);

extern CAPIHook hook_glBindBuffer;
extern CAPIHook hook_glBufferData;
extern CAPIHook hook_glGenBuffers;
extern CAPIHook hook_glDeleteBuffers;

struct BufferID {
    BufferID() : glBufferID(0), nextFreeIndex(0) {}

    int glBufferID;
    int nextFreeIndex;
};

unsigned int currentBufferID = 0;
unsigned int currentFreeIndex = 0; // 0 is reserved
unsigned int MAX_VISIT = 0x500;

std::vector<BufferID> bufferIDs;
std::tr1::unordered_map<std::string, unsigned int> mapDataToBufferID;

struct BufferRef {
    BufferRef() : ref(0), nextFreeIndex(0) {}

    int ref;
    int nextFreeIndex;
    std::tr1::unordered_map<std::string, unsigned int>::iterator iterator;
};

std::vector<BufferRef> bufferRefs;
unsigned int currentFreeBufferRef = 0;

void _stdcall

Proxy_glBindBuffer(int target, unsigned int buffer) {
    currentBufferID = buffer;
    ((PFNGLBINDBUFFERARBPROC)(PROC)
    hook_glBindBuffer)(target, bufferIDs[currentBufferID].glBufferID);
}

inline void CheckRef(unsigned int id) {
    unsigned int org = bufferIDs[currentBufferID].glBufferID;
    if (org != id) {
        bufferRefs[id].ref++;
        bufferIDs[currentBufferID].glBufferID = id;
        if (org != 0) {
            bufferRefs[org].ref--;
            if (bufferRefs[org].ref == 0) {
                //	printf("DROP INDEX: %d\n", org);
                bufferRefs[org].nextFreeIndex = currentFreeBufferRef;
                currentFreeBufferRef = org;
                mapDataToBufferID.erase(bufferRefs[org].iterator);
            }
        }
    }
}

void _stdcall

Proxy_glBufferData(int target, int size, const void *data, int usage) {
    std::string content((const char *) data, size);
    content.append(std::string((const char *) &target, sizeof(target)));

    std::tr1::unordered_map<std::string, unsigned int>::iterator p = mapDataToBufferID.find(content);
    if (p != mapDataToBufferID.end()) {
        unsigned int id = p->second;
        ((PFNGLBINDBUFFERARBPROC)(PROC)
        hook_glBindBuffer)(target, id);
        CheckRef(id);
        // printf("REUSE!!!! %d\n", id);
    } else {
        // Allocate gl buffer id
        unsigned int id = 0;
        if (currentFreeBufferRef != 0) {
            id = currentFreeBufferRef;
            currentFreeBufferRef = bufferRefs[id].nextFreeIndex;
        } else {
            ((PFNGLGENBUFFERSARBPROC)(PROC)
            hook_glGenBuffers)(1, &id);
            if (bufferRefs.size() <= id) {
                bufferRefs.resize(id + 1);
            }
        }

        ((PFNGLBINDBUFFERARBPROC)(PROC)
        hook_glBindBuffer)(target, id);
        ((PFNGLBUFFERDATAARBPROC)(PROC)
        hook_glBufferData)(target, size, data, usage);

        // connect
        CheckRef(id);

        bufferRefs[id].iterator = mapDataToBufferID.insert(std::make_pair(content, id)).first;
        //	printf("ALLOCATE!!!! %d\n", id);
    }
}

void _stdcall

Proxy_glGenBuffers(int n, unsigned int *buffers) {
    while (n-- > 0) {
        if (currentFreeIndex != 0) {
            unsigned int p = currentFreeIndex;
            *buffers++ = p;
            currentFreeIndex = bufferIDs[p].nextFreeIndex;
            bufferIDs[p].nextFreeIndex = 0;
        } else {
            // generate new one
            *buffers++ = bufferIDs.size();
            bufferIDs.push_back(BufferID());
        }
    }
}

void _stdcall

Proxy_glDeleteBuffers(int n, const unsigned int *buffers) {
    for (int i = 0; i < n; i++) {
        unsigned int id = buffers[i];
        bufferIDs[id].nextFreeIndex = currentFreeIndex;
        currentFreeIndex = id;
    }

    // ((PFNGLDELETEBUFFERSARBPROC)(PROC)hook_glDeleteBuffers)(n, buffers);
}

CAPIHook hook_glBindBuffer("libglesv2.dll", "glBindBuffer", (PROC) Proxy_glBindBuffer);
CAPIHook hook_glBufferData("libglesv2.dll", "glBufferData", (PROC) Proxy_glBufferData);
CAPIHook hook_glGenBuffers("libglesv2.dll", "glGenBuffers", (PROC) Proxy_glGenBuffers);
CAPIHook hook_glDeleteBuffers("libglesv2.dll", "glDeleteBuffers", (PROC) Proxy_glDeleteBuffers);

void RedirectOpenGLEntries() {
    bufferIDs.push_back(BufferID()); // reserved.
    bufferRefs.push_back(BufferRef());
}

#pragma endregion OpenGL