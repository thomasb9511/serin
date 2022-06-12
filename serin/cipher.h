// serin

#pragma once

#include <cryptopp/3way.h>

namespace serin
{
    namespace cipher
    {
        namespace ies
        {
        }

        namespace aesgcm
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace aesgcm
        namespace aesctr
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr);
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr);
        } // namespace aesctr

        namespace ctr
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr);
        } // namespace ctr

        namespace cbc
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace cbc

        namespace xts
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace xts

        namespace cfb
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace cfb

        namespace ofb
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace ofb

        namespace cts
        {
            template <typename F>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);

            template <typename F>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv);
        } // namespace cts

        namespace aead
        {
            namespace gcm
            {
                template <typename F>
                CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

                template <typename F>
                CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
            } // namespace gcm

            namespace eax
            {
                template <typename F>
                CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

                template <typename F>
                CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
            } // namespace eax
        }     // namespace aead
    }         // namespace cipher
} // namespace serin
