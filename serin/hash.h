// serin

#pragma once

#include <string>
#include <cryptopp/secblock.h>

namespace serin
{
    namespace hash
    {
        template <typename F>
        std::string hmac(std::string& input, CryptoPP::SecByteBlock& key)
        {
            std::string mac, encoded;

            CryptoPP::HMAC<F> hmac(key, key.size());

            CryptoPP::StringSource ss2(input, true,
                                       new CryptoPP::HashFilter(hmac, new CryptoPP::StringSink(mac)) // HashFilter
                );                                                                                   // StringSource

            encoded.clear();

            return mac;
        }

        template <typename F>
        std::string hash(std::string& input)
        {
            const CryptoPP::byte* pbData   = (CryptoPP::byte*)input.data();
            size_t                nDataLen = input.length();
            CryptoPP::byte        abDigest[F::DIGESTSIZE];

            F().CalculateDigest(abDigest, pbData, nDataLen);

            return std::string(static_cast<char*>(abDigest), F::DIGESTSIZE);
        }

        template <typename F>
        CryptoPP::SecByteBlock hash(CryptoPP::SecByteBlock& input)
        {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            F().CalculateDigest(abDigest, input, input.size());

            return abDigest;
        }

        template <typename F>
        CryptoPP::SecByteBlock hmac(CryptoPP::SecByteBlock& input, CryptoPP::SecByteBlock& key)
        {
            CryptoPP::HMAC<F> hmac(key, key.size());
            hmac.Update(input, input.size());

            CryptoPP::SecByteBlock d(CryptoPP::HMAC<F>::DIGESTSIZE);

            hmac.Final(d);

            return d;
        }

        template <typename F>
        CryptoPP::SecByteBlock hkdf(CryptoPP::SecByteBlock& password, std::string& salt, std::string& deriv)
        {
            auto   salt_((const CryptoPP::byte*)salt.data());
            size_t slen = strlen((const char*)salt_);

            auto   deriv_((const CryptoPP::byte*)deriv.data());
            size_t ilen = strlen((const char*)deriv_);

            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            CryptoPP::HKDF<F> hkdf;

            hkdf.DeriveKey(abDigest, abDigest.size(), password, password.size(), salt_, slen, deriv_, ilen);

            return abDigest; // @suppress("Ambiguous problem") // @suppress("Symbol is not resolved")
        }
    } // namespace hash
}     // namespace serin
