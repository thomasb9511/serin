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
        std::string hash(const std::string& input) {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            try
            {
                F hash;

                CryptoPP::StringSource f((input), true,
                                         new CryptoPP::HashFilter(
                                             hash, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
            }
            catch (CryptoPP::InvalidArgument& e)
            {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch (CryptoPP::Exception& e)
            {
                std::cerr << "Caught Exception..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }

            return std::string(reinterpret_cast<char*>(abDigest.data()), F::DIGESTSIZE);
        }

        template <typename F>
        std::string hmac(const std::string& input, const CryptoPP::SecByteBlock& key) {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            try
            {
                CryptoPP::HMAC<F> hmac(key, key.size());

                CryptoPP::StringSource f((input), true,
                                         new CryptoPP::HashFilter(
                                             hmac, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
            }
            catch (CryptoPP::InvalidArgument& e)
            {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch (CryptoPP::Exception& e)
            {
                std::cerr << "Caught Exception..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }

            return std::string(reinterpret_cast<char*>(abDigest.data()), F::DIGESTSIZE);
        }

        template <typename F>
        CryptoPP::SecByteBlock hash(const CryptoPP::SecByteBlock& input) {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            try
            {
                F hash;

                CryptoPP::ArraySource f((input.data(), input.size()), true,
                                        new CryptoPP::HashFilter(
                                            hash, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
            }
            catch (CryptoPP::InvalidArgument& e)
            {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch (CryptoPP::Exception& e)
            {
                std::cerr << "Caught Exception..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }

            return abDigest;
        }

        template <typename F>
        CryptoPP::SecByteBlock hmac(const CryptoPP::SecByteBlock& input, const CryptoPP::SecByteBlock& key) {
            CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

            try
            {
                CryptoPP::HMAC<F> hmac(key, key.size());

                CryptoPP::ArraySource f((input.data(), input.size()), true,
                                        new CryptoPP::HashFilter(
                                            hmac, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
            }
            catch (CryptoPP::InvalidArgument& e)
            {
                std::cerr << "Caught InvalidArgument..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            } catch (CryptoPP::Exception& e)
            {
                std::cerr << "Caught Exception..." << std::endl;
                std::cerr << e.what() << std::endl;
                std::cerr << std::endl;
            }

            return abDigest;
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
            std::string hash(const std::string& filename) {
                CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

                try
                {
                    F hash;

                    CryptoPP::FileSource f((filename.c_str()), true,
                                           new CryptoPP::HashFilter(
                                               hash, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
                }
                catch (CryptoPP::InvalidArgument& e)
                {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e)
                {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return std::string(reinterpret_cast<char*>(abDigest.data()), F::DIGESTSIZE);
            }

            template <typename F>
            std::string hmac(const std::string& filename, const CryptoPP::SecByteBlock& key) {
                CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

                try
                {
                    CryptoPP::HMAC<F> hmac(key, key.size());

                    CryptoPP::FileSource f((filename.c_str()), true,
                                           new CryptoPP::HashFilter(
                                               hmac, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
                }
                catch (CryptoPP::InvalidArgument& e)
                {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e)
                {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return std::string(reinterpret_cast<char*>(abDigest.data()), F::DIGESTSIZE);
            }

            template <typename F>
            CryptoPP::SecByteBlock hash_bytes(const std::string& filename) {
                CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

                try
                {
                    F hash;

                    CryptoPP::FileSource f((filename.c_str()), true,
                                           new CryptoPP::HashFilter(
                                               hash, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
                }
                catch (CryptoPP::InvalidArgument& e)
                {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e)
                {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return abDigest;
            }

            template <typename F>
            CryptoPP::SecByteBlock hmac_bytes(const std::string& filename, const CryptoPP::SecByteBlock& key) {
                CryptoPP::SecByteBlock abDigest(F::DIGESTSIZE);

                try
                {
                    CryptoPP::HMAC<F> hmac(key, key.size());

                    CryptoPP::FileSource f((filename.c_str()), true,
                                           new CryptoPP::HashFilter(
                                               hmac, new CryptoPP::ArraySink(abDigest, F::DIGESTSIZE)));
                }
                catch (CryptoPP::InvalidArgument& e)
                {
                    std::cerr << "Caught InvalidArgument..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::Exception& e)
                {
                    std::cerr << "Caught Exception..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                }

                return abDigest;
            }
        }
    }
}
