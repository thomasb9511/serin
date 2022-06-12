// serin

#pragma once

#include <iomanip>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>

#include "serin.h"

namespace serin
{
    namespace rng
    {
        class CombinedRNG : public CryptoPP::RandomNumberGenerator
        {
        public:
            CombinedRNG(RandomNumberGenerator& rng1, RandomNumberGenerator& rng2):
                m_rng1(rng1), m_rng2(rng2) { }

            bool CanIncorporateEntropy() const override
            {
                return m_rng1.CanIncorporateEntropy() || m_rng2.CanIncorporateEntropy();
            }

            void IncorporateEntropy(const CryptoPP::byte* input, size_t length) override
            {
                if (m_rng1.CanIncorporateEntropy())
                    m_rng1.IncorporateEntropy(input, length);
                if (m_rng2.CanIncorporateEntropy())
                    m_rng2.IncorporateEntropy(input, length);
            }

            void GenerateBlock(CryptoPP::byte* output, size_t size) override
            {
                CryptoPP::RandomNumberSource(m_rng1, size, true, new CryptoPP::ArraySink(output, size));
                CryptoPP::RandomNumberSource(m_rng2, size, true, new CryptoPP::ArrayXorSink(output, size));
            }

        private:
            RandomNumberGenerator& m_rng1,& m_rng2;
        };

        sympack                rand_sympack();
        CryptoPP::SecByteBlock randblock(int bytes);

        std::string randstrng(int len);
        std::string rdprime(unsigned int bytes);

        namespace RDSEED
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(int bytes);

            std::string randstrng(int len);
            std::string rdprime(unsigned int bytes);
        } // namespace RDSEED

        namespace RDRAND
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(int bytes);

            std::string randstrng(int len);
            std::string rdprime(unsigned int bytes);
        } // namespace RDRAND

        namespace X917
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(int bytes);

            std::string randstrng(int len);
            std::string rdprime(unsigned int bytes);
        } // namespace X917

        namespace X931
        {
            sympack                rand_sympack();
            CryptoPP::SecByteBlock randblock(int bytes);

            std::string randstrng(int len);
            std::string rdprime(unsigned int bytes);
        } // namespace X931
    }     // namespace rng
}         // namespace serin
