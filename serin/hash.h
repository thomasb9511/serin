// serin

#pragma once

#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>

namespace serin
{
    namespace hash
    {
        template <typename F>
        std::string hmac(std::string& input, CryptoPP::SecByteBlock& key) {
            std::string mac, encoded;

            CryptoPP::HMAC<F> hmac(key, key.size());

            CryptoPP::StringSource ss2(input, true,
                                       new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
                );                                                                                   // StringSource

            encoded.clear();

            return mac;
        }

        template <typename F>
        std::string hash(std::string& input) {
            auto           pbData   = reinterpret_cast<const CryptoPP::byte*>(input.data());
            size_t         nDataLen = input.length();
            CryptoPP::byte abDigest[F::DIGESTSIZE];

            F().CalculateDigest(abDigest, pbData, nDataLen);

            return std::string(static_cast<char*>(abDigest), F::DIGESTSIZE);
        }

        template <typename F>
        CryptoPP::SecByteBlock hash(CryptoPP::SecByteBlock& input) {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            F().CalculateDigest(abDigest, input, input.size());

            return abDigest;
        }

        template <typename F>
        CryptoPP::SecByteBlock hmac(CryptoPP::SecByteBlock& input, CryptoPP::SecByteBlock& key) {
            CryptoPP::HMAC<F> hmac(key, key.size());
            hmac.Update(input, input.size());

            CryptoPP::SecByteBlock d(CryptoPP::HMAC<F>::DIGESTSIZE);

            hmac.Final(d);

            return d;
        }

        template <typename F>
        CryptoPP::SecByteBlock hkdf(CryptoPP::SecByteBlock& password, std::string& salt, std::string& deriv) {
            CryptoPP::SecByteBlock salt_(reinterpret_cast<const CryptoPP::byte*>(salt.data()));

            CryptoPP::SecByteBlock deriv_(reinterpret_cast<const CryptoPP::byte*>(deriv.data()));

            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            CryptoPP::HKDF<F> hkdf;

            hkdf.DeriveKey(abDigest, abDigest.size(), password, password.size(), salt_, salt_.size(), deriv_,
                           deriv_.size());

            return abDigest; // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
        }

        namespace files
        {
            template <typename F>
            std::string hmac(std::string& filename, CryptoPP::SecByteBlock& key) {
                std::string mac, encoded;

                CryptoPP::HMAC<F> hmac(key, key.size());

                CryptoPP::StringSource ss2(filename, true,
                                           new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
                    );                                                                                   // StringSource

                encoded.clear();

                return mac;
            }

            template <typename F>
            std::string hash(std::string& filename) {
                CryptoPP::byte abDigest[F::DIGESTSIZE];

                F hash;

                CryptoPP::FileSource f((filename.c_str()), true,
                                       new CryptoPP::HashFilter(
                                           hash, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));

                return std::string(reinterpret_cast<char*>(abDigest), F::DIGESTSIZE);
            }

            template <typename F>
            CryptoPP::SecByteBlock hash(CryptoPP::SecByteBlock& filename) {
                CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

                F().CalculateDigest(abDigest, filename, filename.size());

                return abDigest;
            }

            template <typename F>
            CryptoPP::SecByteBlock hmac(CryptoPP::SecByteBlock& filename, CryptoPP::SecByteBlock& key) {
                CryptoPP::HMAC<F> hmac(key, key.size());
                hmac.Update(filename, filename.size());

                CryptoPP::SecByteBlock d(CryptoPP::HMAC<F>::DIGESTSIZE);

                hmac.Final(d);

                return d;
            }
        } // namespace files
    }     // namespace hash
}         // namespace serin
