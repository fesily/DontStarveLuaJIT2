import argparse
from typing import Dict

# Lua 里那张 p 表（字符->值）对应的“值->字符”字母表（按 0..63 顺序）
LUA_ALPHABET = "/gcSWTPtvB3rfGCeI8aAKD1FQjmNuJobn25ZXspUklV+RYEOy7w6dqi49MHhxL0z"


def _build_dec_table(alphabet: str) -> Dict[str, int]:
    if len(alphabet) != 64:
        raise ValueError(f"alphabet length must be 64, got {len(alphabet)}")
    if len(set(alphabet)) != 64:
        raise ValueError("alphabet must contain 64 unique characters")
    return {ch: idx for idx, ch in enumerate(alphabet)}


def decode_custom_b64(text: str, alphabet: str, *, strict_padding: bool = False) -> bytes:
    dec = _build_dec_table(alphabet)

    out = bytearray()
    v = 0  # 24-bit accumulator
    w = 0  # how many sextets collected in current 4-group (0..3)

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in dec:
            y = dec[ch]
            v += y * (64 ** (3 - w))
            w += 1
            if w == 4:
                out.append((v // 65536) & 0xFF)
                out.append((v // 256) & 0xFF)
                out.append(v & 0xFF)
                v = 0
                w = 0
        elif ch == "=":
            # 收尾：Lua 代码遇到 '=' 就输出高字节，若后面不是第二个 '=' 再输出中间字节
            out.append((v // 65536) & 0xFF)

            next_is_eq = (i + 1 < n and text[i + 1] == "=")
            if not next_is_eq:
                out.append((v // 256) & 0xFF)

            if strict_padding:
                # 可选：严格模式下，要求 '=' 必须出现在 2 或 3 个 sextet 之后
                if w not in (2, 3):
                    raise ValueError(f"invalid padding position (w={w})")

            break
        else:
            # 忽略其它字符（换行/空格/噪声）
            pass

        i += 1

    return bytes(out)


def encode_custom_b64(data: bytes, alphabet: str) -> str:
    _ = _build_dec_table(alphabet)  # validate
    out = []

    i = 0
    n = len(data)
    while i < n:
        chunk = data[i:i + 3]
        b = chunk + b"\x00" * (3 - len(chunk))
        v = (b[0] << 16) | (b[1] << 8) | b[2]

        c0 = (v >> 18) & 0x3F
        c1 = (v >> 12) & 0x3F
        c2 = (v >> 6) & 0x3F
        c3 = v & 0x3F

        out.append(alphabet[c0])
        out.append(alphabet[c1])

        if len(chunk) == 1:
            out.append("=")
            out.append("=")
        elif len(chunk) == 2:
            out.append(alphabet[c2])
            out.append("=")
        else:
            out.append(alphabet[c2])
            out.append(alphabet[c3])

        i += 3

    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["enc", "dec"])
    ap.add_argument("text", help="enc: treat as utf-8 text; dec: encoded text")
    ap.add_argument("--alphabet", default=LUA_ALPHABET, help="64-char alphabet (0..63 -> char)")
    ap.add_argument("--strict-padding", action="store_true")
    ap.add_argument("--out", choices=["utf8", "hex", "raw"], default="utf8",
                    help="dec output format: utf8/hex/raw")
    args = ap.parse_args()

    if args.mode == "dec":
        data = decode_custom_b64(args.text, args.alphabet, strict_padding=args.strict_padding)
        if args.out == "hex":
            print(data.hex())
        elif args.out == "raw":
            # Windows 终端可能会因编码显示异常；需要就用重定向到文件
            import sys
            sys.stdout.buffer.write(data)
        else:
            print(data.decode("utf-8", errors="replace"))
    else:
        data = args.text.encode("utf-8")
        print(encode_custom_b64(data, args.alphabet))


if __name__ == "__main__":
    main()