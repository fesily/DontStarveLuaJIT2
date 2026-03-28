#pragma once
#include <string_view>

enum class DstAngleBackend {
    Auto,
    D3D11 = Auto,
    D3D9,
    Vulkan,
    GLES,
    OpenGL,
    Metal,
    Unknown,
};

inline DstAngleBackend from_string(std::string_view str) {
    // first check number
    if (str == "d3d11") {
        return DstAngleBackend::D3D11;
    } else if (str == "d3d9") {
        return DstAngleBackend::D3D9;
    } else if (str == "vulkan") {
        return DstAngleBackend::Vulkan;
    } else if (str == "gles") {
        return DstAngleBackend::GLES;
    } else if (str == "gl" || str == "opengl") {
        return DstAngleBackend::OpenGL;
    } else if (str == "metal") {
        return DstAngleBackend::Metal;
    } else if (str == "0") {
        return DstAngleBackend::D3D11;
    } else if (str == "1") {
        return DstAngleBackend::D3D9;
    } else if (str == "2") {
        return DstAngleBackend::Vulkan;
    } else if (str == "3") {
        return DstAngleBackend::GLES;
    } else if (str == "4") {
        return DstAngleBackend::OpenGL;
    } else if (str == "5") {
        return DstAngleBackend::Metal;
    }
    return DstAngleBackend::Unknown;
}

inline std::string_view to_string(DstAngleBackend backend) {
    using namespace std::string_view_literals;
    switch (backend) {
    case DstAngleBackend::D3D11:
        return "d3d11"sv;
    case DstAngleBackend::D3D9:
        return "d3d9"sv;
    case DstAngleBackend::Vulkan:
        return "vulkan"sv;
    case DstAngleBackend::GLES:
        return "gles"sv;
    case DstAngleBackend::OpenGL:
        return "opengl"sv;
    case DstAngleBackend::Metal:
        return "metal"sv;
    default:
        return "unknown"sv;
    }
}
