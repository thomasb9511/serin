// serin

#pragma once

#include <cryptopp/secblock.h>

namespace serin
{
    const std::string VERSION = "1.00";
    const std::string GUID    = "31D70008-DDC4-4D41-86A2-04F2F902865E";

    using secure_string = std::basic_string<char, std::char_traits<char>, CryptoPP::AllocatorWithCleanup<char>>;

    constexpr unsigned int b512 = 64;
    constexpr unsigned int b480 = 60;
    constexpr unsigned int b448 = 56;
    constexpr unsigned int b416 = 52;
    constexpr unsigned int b384 = 48;
    constexpr unsigned int b352 = 44;
    constexpr unsigned int b320 = 40;
    constexpr unsigned int b288 = 36;
    constexpr unsigned int b256 = 32;
    constexpr unsigned int b224 = 28;
    constexpr unsigned int b192 = 24;
    constexpr unsigned int b160 = 20;
    constexpr unsigned int b128 = 16;
    constexpr unsigned int b96  = 12;
    constexpr unsigned int b64  = 8;
    constexpr unsigned int b32  = 4;

    struct sympack
    {
        CryptoPP::SecByteBlock key;
        CryptoPP::SecByteBlock iv;
    };

    template <typename F, typename T>
    CryptoPP::SecByteBlock prompt(char bit);

    void SetStdinEcho(bool enable);
} // namespace serin
