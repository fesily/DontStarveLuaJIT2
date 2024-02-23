#include "PersistentString.hpp"
#include <string_view>
#include <memory>
#include <zlib.h>
using namespace std::literals;

// Base64字符集
constexpr auto base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"sv;

// 将字符串编码为Base64格式
std::string base64_encode(const unsigned char *input, size_t length)
{
    std::string encoded;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    while (length--)
    {
        char_array_3[i++] = *(input++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0]) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1]) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2]) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0]) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1]) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2]) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while (i++ < 3)
            encoded += '=';
    }

    return encoded;
}

// 将Base64格式解码为字符串
std::string base64_decode(const std::string_view &encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string decoded;

    while (in_len-- && (encoded_string[in_] != '=') && (std::isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/')))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] >> 4) & 0x3);
            char_array_3[1] = (char_array_4[1] << 4) ^ ((char_array_4[2] >> 2) & 0xf);
            char_array_3[2] = (char_array_4[2] << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] >> 4) & 0x3);
        char_array_3[1] = (char_array_4[1] << 4) ^ ((char_array_4[2] >> 2) & 0xf);
        char_array_3[2] = (char_array_4[2] << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++)
            decoded += char_array_3[j];
    }

    return decoded;
}
struct encode_head
{
    int64_t version = 0x1000000001;
    int32_t original_len;
    int32_t zlib_len;
};
constexpr auto file_head = "KLEI     1"sv;
constexpr auto encode_flag = 'D';
std::expected<std::string, std::string> GetPersistentString(const std::string_view &filename)
{
    auto fp = fopen(filename.data(), "r");
    if (!fp)
        return std::unexpected(strerror(errno));
    fseek(fp, 0, SEEK_END);
    auto length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    auto buffer_ptr = std::make_unique<char[]>(length + 1);
    auto buffer = buffer_ptr.get();
    auto readeds = fread(buffer, sizeof(char), length, fp);
    if (readeds <= 0)
        return std::unexpected(strerror(errno));
    buffer[readeds] = 0;
    auto head_str = std::string_view(buffer, file_head.size());
    if (head_str != file_head)
    {
        return std::unexpected("unkown header:" + std::string(head_str));
    }
    if (buffer[file_head.size()] != encode_flag)
        return {buffer + file_head.size()};
    auto zlib_buffer = base64_decode({buffer + file_head.size() + 1, readeds - file_head.size() - 1});
    auto head = (const encode_head *const)zlib_buffer.data();
    auto body = (Bytef *)(head + 1);
    if (head->version != encode_head{}.version)
    {
        return std::unexpected("unknown version:" + std::to_string(head->version));
    }
    uLongf original_len = head->original_len;
    std::string original_buffer;
    original_buffer.resize(original_len + 1);
    if (uncompress((Bytef *)original_buffer.data(), &original_len, body, head->zlib_len) != Z_OK)
    {
        return std::unexpected("uncompress error");
    }
    return original_buffer;
}
bool SetPersistentString(const std::string_view &filename, const std::string_view &data, bool encode)
{
    auto fp = fopen(filename.data(), "w");
    if (!fp)
        return false;
    if (fwrite(file_head.data(), sizeof(char), file_head.size(), fp) != file_head.size())
    {
        return false;
    }
    if (!encode)
        return fwrite(data.data(), sizeof(char), data.size(), fp) == data.size();
    auto flag = encode_flag;
    if (fwrite(&flag, sizeof(char), 1, fp) != 1)
    {
        return false;
    }
    encode_head head;
    head.original_len = data.length();
    auto zlib_len = compressBound(data.length());
    head.zlib_len = zlib_len;
    auto buffer_ptr = std::make_unique<Bytef[]>(zlib_len);
    if (compress(buffer_ptr.get(), &zlib_len, (Bytef *)data.data(), data.length()) != Z_OK)
        return false;
    auto output = base64_encode(buffer_ptr.get(), zlib_len);
    return fwrite(output.data(), sizeof(char), output.length(), fp) == output.length();
}