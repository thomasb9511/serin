// serin

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rdrand.h>

#include "serin.h"

#include "rng.h"

namespace serin
{
    namespace rng
    {
        CryptoPP::SecByteBlock randblock(const int bytes)
        {
            CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(CryptoPP::AES::BLOCKSIZE);
            OS_GenerateRandomBlock(false, key, key.size());
            OS_GenerateRandomBlock(false, seed, seed.size());
            CryptoPP::X917RNG xAES(new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH), seed, NULLPTR);

            CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
            CryptoPP::AutoSeededX917RNG<CryptoPP::AES>      x931;

            CryptoPP::RDRAND rdrand;

            CryptoPP::RDSEED rdseed;

            CombinedRNG rng1(x917, x931);
            CombinedRNG rng2(rdseed, rdrand);
            CombinedRNG rng3(rng1, rng2);
            CombinedRNG prng(rng3, xAES);

            CryptoPP::SecByteBlock randomBytes(bytes);

            prng.GenerateBlock(randomBytes, bytes);

            return randomBytes;
        }

        std::string randstrng(const int len)
        {
            CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(CryptoPP::AES::BLOCKSIZE);
            OS_GenerateRandomBlock(false, key, key.size());
            OS_GenerateRandomBlock(false, seed, seed.size());
            CryptoPP::X917RNG xAES(new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH), seed, NULLPTR);

            CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
            CryptoPP::AutoSeededX917RNG<CryptoPP::AES>      x931;

            CryptoPP::RDRAND rdrand;

            CryptoPP::RDSEED rdseed;

            CombinedRNG rng1(x917, x931);
            CombinedRNG rng2(rdseed, rdrand);
            CombinedRNG rng3(rng1, rng2);
            CombinedRNG prng(rng3, xAES);

            CryptoPP::SecByteBlock Bytes(len);

            prng.GenerateBlock(Bytes, len);

            std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());

            return randomBytes;
        }

        std::string rdprime(unsigned int bytes)
        {
            int size8 = bytes * 8;

            CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH), seed(CryptoPP::AES::BLOCKSIZE);
            OS_GenerateRandomBlock(false, key, key.size());
            OS_GenerateRandomBlock(false, seed, seed.size());
            CryptoPP::X917RNG xAES(new CryptoPP::AES::Encryption(key, CryptoPP::AES::MAX_KEYLENGTH), seed, NULLPTR);

            CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> x917;
            CryptoPP::AutoSeededX917RNG<CryptoPP::AES>      x931;

            CryptoPP::RDRAND rdrand;

            CryptoPP::RDSEED rdseed;

            CombinedRNG rng1(x917, x931);
            CombinedRNG rng2(rdseed, rdrand);
            CombinedRNG rng3(rng1, rng2);
            CombinedRNG prng(rng3, xAES);

            CryptoPP::Integer x;

            CryptoPP::AlgorithmParameters params
                = CryptoPP::MakeParameters("BitLength", size8)("RandomNumberType", CryptoPP::Integer::PRIME);

            x.GenerateRandom(prng, params);

            std::stringstream tempbuf;

            tempbuf << std::hex << std::uppercase << x << std::dec;

            std::string temp(tempbuf.str());

            std::stringstream buf;

            buf << "0x" << std::setfill('0') << std::setw(2 * static_cast<std::streamsize>(bytes) + 1) << temp;

            std::string str(buf.str());

            str.resize(str.size() - 1);

            return str;
        }

        sympack rand_sympack()
        {
            const CryptoPP::SecByteBlock key = randblock(CryptoPP::AES::DEFAULT_KEYLENGTH);
            const CryptoPP::SecByteBlock iv  = randblock(CryptoPP::AES::BLOCKSIZE);

            sympack a = {key, iv};

            return a;
        }

        namespace RDRAND
        {
            CryptoPP::SecByteBlock randblock(const int bytes)
            {
                CryptoPP::RDRAND prng;

                CryptoPP::SecByteBlock randomBytes(bytes);

                prng.GenerateBlock(randomBytes, bytes);

                return randomBytes;
            }

            std::string randstrng(const int len)
            {
                CryptoPP::RDRAND prng;

                CryptoPP::SecByteBlock Bytes(len);

                prng.GenerateBlock(Bytes, len);

                std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());

                return randomBytes;
            }

            std::string rdprime(unsigned int bytes)
            {
                const int size8 = bytes * 8;

                CryptoPP::RDRAND prng;

                CryptoPP::Integer x;

                const CryptoPP::AlgorithmParameters params
                    = CryptoPP::MakeParameters("BitLength", size8)("RandomNumberType", CryptoPP::Integer::PRIME);

                x.GenerateRandom(prng, params);

                std::stringstream tempbuf;

                tempbuf << std::hex << std::uppercase << x << std::dec;

                const std::string temp(tempbuf.str());

                std::stringstream buf;

                buf << "0x" << std::setfill('0') << std::setw(static_cast<std::streamsize>(bytes) * 2 + 1) << temp;

                std::string str(buf.str());

                str.resize(str.size() - 1);

                return str;
            }

            sympack rand_sympack()
            {
                const CryptoPP::SecByteBlock key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
                const CryptoPP::SecByteBlock iv  = randblock(CryptoPP::AES::BLOCKSIZE);

                return {key, iv};
            }
        } // namespace RDRAND

        namespace RDSEED
        {
            CryptoPP::SecByteBlock randblock(const int bytes)
            {
                CryptoPP::RDSEED prng;

                CryptoPP::SecByteBlock randomBytes(bytes);

                prng.GenerateBlock(randomBytes, bytes);

                return randomBytes;
            }

            std::string randstrng(const int len)
            {
                CryptoPP::RDSEED prng;

                CryptoPP::SecByteBlock Bytes(len);

                prng.GenerateBlock(Bytes, len);

                std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());

                return randomBytes;
            }

            std::string rdprime(unsigned int bytes)
            {
                const int size8 = bytes * 8;

                CryptoPP::RDSEED prng;

                CryptoPP::Integer x;

                const CryptoPP::AlgorithmParameters params
                    = CryptoPP::MakeParameters("BitLength", size8)("RandomNumberType", CryptoPP::Integer::PRIME);

                x.GenerateRandom(prng, params);

                std::stringstream tempbuf;

                tempbuf << std::hex << std::uppercase << x << std::dec;

                const std::string temp(tempbuf.str());

                std::stringstream buf;

                buf << "0x" << std::setfill('0') << std::setw(2 * static_cast<std::streamsize>(bytes) + 1) << temp;

                std::string str(buf.str());

                str.resize(str.size() - 1);

                return str;
            }

            sympack rand_sympack()
            {
                const CryptoPP::SecByteBlock key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
                const CryptoPP::SecByteBlock iv  = randblock(CryptoPP::AES::BLOCKSIZE);

                return {key, iv};
            }
        } // namespace RDSEED

        namespace X931
        {
            CryptoPP::SecByteBlock randblock(const int bytes)
            {
                CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

                CryptoPP::SecByteBlock randomBytes(bytes);

                prng.GenerateBlock(randomBytes, bytes);

                return randomBytes;
            }

            std::string randstrng(const int len)
            {
                CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

                CryptoPP::SecByteBlock Bytes(len);

                prng.GenerateBlock(Bytes, len);

                std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());

                return randomBytes;
            }

            std::string rdprime(unsigned int bytes)
            {
                int size8 = bytes * 8;

                CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;

                CryptoPP::Integer x;

                CryptoPP::AlgorithmParameters params
                    = CryptoPP::MakeParameters("BitLength", size8)("RandomNumberType", CryptoPP::Integer::PRIME);

                x.GenerateRandom(prng, params);

                std::stringstream tempbuf;

                tempbuf << std::hex << std::uppercase << x << std::dec;

                std::string temp(tempbuf.str());

                std::stringstream buf;

                buf << "0x" << std::setfill('0') << std::setw(bytes * 2 + 1) << temp;

                std::string str(buf.str());

                str.resize(str.size() - 1);

                return str;
            }

            sympack rand_sympack()
            {
                const CryptoPP::SecByteBlock key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
                const CryptoPP::SecByteBlock iv  = randblock(CryptoPP::AES::BLOCKSIZE);

                return {key, iv};
            }
        } // namespace X931

        namespace X917
        {
            CryptoPP::SecByteBlock randblock(const int bytes)
            {
                CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

                CryptoPP::SecByteBlock randomBytes(bytes);

                prng.GenerateBlock(randomBytes, bytes);

                return randomBytes;
            }

            std::string randstrng(const int len)
            {
                CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

                CryptoPP::SecByteBlock Bytes(len);

                prng.GenerateBlock(Bytes, len);

                std::string randomBytes(reinterpret_cast<const char*>(Bytes.data()), Bytes.size());

                return randomBytes;
            }

            std::string rdprime(unsigned int bytes)
            {
                int size8 = bytes * 8;

                CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> prng;

                CryptoPP::Integer x;

                CryptoPP::AlgorithmParameters params
                    = CryptoPP::MakeParameters("BitLength", size8)("RandomNumberType", CryptoPP::Integer::PRIME);

                x.GenerateRandom(prng, params);

                std::stringstream tempbuf;

                tempbuf << std::hex << std::uppercase << x << std::dec;

                std::string temp(tempbuf.str());

                std::stringstream buf;

                buf << "0x" << std::setfill('0') << std::setw(bytes * 2 + 1) << temp;

                std::string str(buf.str());

                str.resize(str.size() - 1);

                return str;
            }

            sympack rand_sympack()
            {
                const CryptoPP::SecByteBlock key = randblock(CryptoPP::AES::MAX_KEYLENGTH);
                const CryptoPP::SecByteBlock iv  = randblock(CryptoPP::AES::BLOCKSIZE);

                return {key, iv};
            }
        } // namespace X917
    }     // namespace rng
} // namespace serin
