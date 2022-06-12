// serin

#pragma once

#include <iostream>
#include <string>

#include <cryptopp/hex.h>

namespace serin
{
    namespace transform
    {
        namespace hex
        {
            std::string to(std::string& input);
            std::string from(std::string& input);

            std::string to(CryptoPP::SecByteBlock& input);
            std::string from(CryptoPP::SecByteBlock& input);

            namespace bytes
            {
                CryptoPP::SecByteBlock to(CryptoPP::SecByteBlock& input);
                CryptoPP::SecByteBlock from(CryptoPP::SecByteBlock& input);
            } // namespace bytes
        }     // namespace hex

        namespace logical
        {
            //std::string xo(std::string& a, std::string& b);

            CryptoPP::SecByteBlock xo(CryptoPP::SecByteBlock& a, CryptoPP::SecByteBlock& b);

            CryptoPP::SecByteBlock interleave(CryptoPP::SecByteBlock& a, CryptoPP::SecByteBlock& b);

            void rotate_(CryptoPP::SecByteBlock& in, unsigned int n);
        } // namespace logical
    }     // namespace transform
}         // namespace serin
