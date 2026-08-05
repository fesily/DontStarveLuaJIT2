#include "PluginHash.hpp"

#include <array>
#include <cstdint>
#include <cctype>
#include <fstream>

namespace ds::plugin_manager {
namespace {

// Compact public-domain-style SHA-256 (FIPS 180-4).
struct Sha256 {
    std::uint32_t state[8]{};
    std::uint64_t bitlen = 0;
    std::uint8_t buffer[64]{};
    size_t buflen = 0;

    Sha256() { reset(); }

    void reset() {
        state[0] = 0x6a09e667u;
        state[1] = 0xbb67ae85u;
        state[2] = 0x3c6ef372u;
        state[3] = 0xa54ff53au;
        state[4] = 0x510e527fu;
        state[5] = 0x9b05688cu;
        state[6] = 0x1f83d9abu;
        state[7] = 0x5be0cd19u;
        bitlen = 0;
        buflen = 0;
    }

    static std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const std::uint8_t block[64]) {
        static const std::uint32_t K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
            0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
            0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
            0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
            0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
            0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<std::uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void update(const std::uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[buflen++] = data[i];
            if (buflen == 64) {
                transform(buffer);
                bitlen += 512;
                buflen = 0;
            }
        }
    }

    void update(std::string_view s) {
        update(reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
    }

    std::array<std::uint8_t, 32> final() {
        bitlen += static_cast<std::uint64_t>(buflen) * 8;
        buffer[buflen++] = 0x80;
        if (buflen > 56) {
            while (buflen < 64) {
                buffer[buflen++] = 0;
            }
            transform(buffer);
            buflen = 0;
        }
        while (buflen < 56) {
            buffer[buflen++] = 0;
        }
        for (int i = 7; i >= 0; --i) {
            buffer[buflen++] = static_cast<std::uint8_t>((bitlen >> (i * 8)) & 0xffu);
        }
        transform(buffer);

        std::array<std::uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<std::uint8_t>((state[i] >> 24) & 0xffu);
            out[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16) & 0xffu);
            out[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8) & 0xffu);
            out[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xffu);
        }
        return out;
    }
};

std::string to_hex(const std::array<std::uint8_t, 32> &bytes) {
    static const char *kHex = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = kHex[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = kHex[bytes[i] & 0xf];
    }
    return out;
}

std::string normalize_hex(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (out.size() >= 2 && out[0] == '0' && out[1] == 'x') {
        out.erase(0, 2);
    }
    return out;
}

} // namespace

std::string sha256_hex(std::string_view data) {
    Sha256 h;
    h.update(data);
    return to_hex(h.final());
}

std::optional<std::string> sha256_file_hex(const std::filesystem::path &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }
    Sha256 h;
    char buf[8192];
    while (in) {
        in.read(buf, sizeof(buf));
        const auto n = in.gcount();
        if (n > 0) {
            h.update(reinterpret_cast<const std::uint8_t *>(buf), static_cast<size_t>(n));
        }
    }
    if (in.bad()) {
        return std::nullopt;
    }
    return to_hex(h.final());
}

bool sha256_hex_equal(std::string_view actual_hex, std::string_view expected_hex) {
    return normalize_hex(actual_hex) == normalize_hex(expected_hex);
}

} // namespace ds::plugin_manager
