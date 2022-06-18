// serin

#include <cassert>
#include <iostream>
#include <string>

#include <cryptopp/3way.h>
#include <cryptopp/aes.h>
#include <cryptopp/aria.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cham.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/des.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>
#include <cryptopp/gcm.h>
#include <cryptopp/gost.h>
#include <cryptopp/hight.h>
#include <cryptopp/idea.h>
#include <cryptopp/lea.h>
#include <cryptopp/mars.h>
#include <cryptopp/modes.h>
#include <cryptopp/rc2.h>
#include <cryptopp/rc5.h>
#include <cryptopp/rc6.h>
#include <cryptopp/safer.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/shark.h>
#include <cryptopp/simeck.h>
#include <cryptopp/simon.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/speck.h>
#include <cryptopp/square.h>
#include <cryptopp/tea.h>
#include <cryptopp/twofish.h>
#include <cryptopp/xts.h>

#include "cipher.h"

namespace serin
{
    namespace cipher
    {
        namespace ies { }

        namespace aesgcm
        {
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv) {
                const int TAG_SIZE = 16;

                // Encrypted, with Tag
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), iv, iv.size());
                    // e.SpecifyDataLengths( 0, pdata.size(), 0 );

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::AuthenticatedEncryptionFilter f1(e, new CryptoPP::Redirector(cipherq), false, TAG_SIZE);
                    plain.TransferTo(f1);
                    f1.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
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

                return ciphertext;
            }

            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& iv) {
                const int TAG_SIZE = 16;

                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    CryptoPP::GCM<CryptoPP::AES>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), iv, iv.size());

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::AuthenticatedDecryptionFilter df(d, new CryptoPP::Redirector(plain),
                                                               CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                                                               TAG_SIZE);
                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    bool b = df.GetLastResult();
                    assert(true == b);

                    plaintext = block;
                }
                catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
                {
                    std::cerr << "Caught HashVerificationFailed..." << std::endl;
                    std::cerr << e.what() << std::endl;
                    std::cerr << std::endl;
                } catch (CryptoPP::InvalidArgument& e)
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

                return plaintext;
            }
        } // namespace aesgcm

        namespace ctr
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::CTR_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::CTR_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace ctr

        namespace cbc
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::CBC_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::CBC_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace cbc

        namespace xts
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::XTS_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::XTS_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace xts

        namespace cfb
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::CFB_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::CFB_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace cfb
        namespace ofb
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::OFB_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::OFB_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace ofb

        namespace cts
        {
            template <typename T>
            CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Ciphertext
                CryptoPP::SecByteBlock ciphertext;

                try
                {
                    typename CryptoPP::CBC_CTS_Mode<T>::Encryption e;
                    e.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    plain.Put(plaintext, plaintext.size());

                    CryptoPP::StreamTransformationFilter ef(e, new CryptoPP::Redirector(cipherq));

                    plain.TransferTo(ef);
                    ef.MessageEnd();

                    CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    cipherq.TransferTo(sink);

                    ciphertext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return ciphertext;
            }

            template <typename T>
            CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                           CryptoPP::SecByteBlock& ctr) {
                // Recovered plaintext
                CryptoPP::SecByteBlock plaintext;

                try
                {
                    typename CryptoPP::CBC_CTS_Mode<T>::Decryption d;
                    d.SetKeyWithIV(key, key.size(), ctr);

                    CryptoPP::ByteQueue plain, cipherq;

                    cipherq.Put(ciphertext, ciphertext.size());

                    CryptoPP::StreamTransformationFilter df(d, new CryptoPP::Redirector(plain));

                    cipherq.TransferTo(df);
                    df.MessageEnd();

                    CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                    CryptoPP::ArraySink    sink(block, block.size());
                    plain.TransferTo(sink);

                    plaintext = block;
                }
                catch (CryptoPP::Exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    exit(1);
                }

                return plaintext;
            }
        } // namespace cts

        namespace aead
        {
            namespace gcm
            {
                template <typename F>
                CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int&                     TAG_SIZE) {
                    CryptoPP::SecByteBlock ciphertext;
                    try
                    {
                        typename CryptoPP::GCM<F>::Encryption e;
                        e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                        // Not required for CryptoPP::GCM mode (but required for CCM mode)
                        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

                        CryptoPP::ByteQueue cipherq;

                        CryptoPP::AuthenticatedEncryptionFilter ef(e, new CryptoPP::Redirector(cipherq), false,
                                                                   TAG_SIZE);

                        // AuthenticatedEncryptionFilter::ChannelPut
                        //  defines two channels: "" (empty) and "AAD"
                        //   channel "" is encrypted and authenticated
                        //   channel "AAD" is authenticated
                        ef.ChannelPut("AAD", iv.data(), iv.size());
                        ef.ChannelMessageEnd("AAD");

                        // Authenticated data *must* be pushed before
                        //  Confidential/Authenticated data. Otherwise
                        //  we must catch the BadState exception
                        ef.ChannelPut("", plaintext.data(), plaintext.size());
                        ef.ChannelMessageEnd("");

                        CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                        CryptoPP::ArraySink    sink(block, block.size());
                        cipherq.TransferTo(sink);

                        ciphertext = block;
                    }
                    catch (CryptoPP::BufferedTransformation::NoChannelSupport& e)
                    {
                        // The tag must go in to the default channel:
                        //  "unknown: this object doesn't support multiple channels"
                        std::cerr << "Caught NoChannelSupport..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
                    {
                        // Pushing PDATA before ADATA results in:
                        //  "GMC/CryptoPP::CryptoPP::AES: Update was called before State_IVSet"
                        std::cerr << "Caught BadState..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::InvalidArgument& e)
                    {
                        std::cerr << "Caught InvalidArgument..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    }
                    return ciphertext;
                }

                template <typename F>
                CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int&                      TAG_SIZE) {
                    CryptoPP::SecByteBlock plaintext;
                    try
                    {
                        typename CryptoPP::GCM<F>::Decryption d;
                        d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

                        // Break the cipher text out into it's
                        //  components: Encrypted Data and MAC Value
                        //CryptoPP::SecByteBlock mac = cipher.substr(cipher.length() - TAG_SIZE);

                        CryptoPP::SecByteBlock enc(ciphertext.data(), ciphertext.size() - TAG_SIZE);
                        CryptoPP::SecByteBlock mac(ciphertext.data() + ciphertext.size() - TAG_SIZE, TAG_SIZE);

                        CryptoPP::ByteQueue plain;

                        CryptoPP::AuthenticatedDecryptionFilter df(d, new CryptoPP::Redirector(plain),
                                                                   CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN
                                                                   | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                                                   TAG_SIZE);

                        // The order of the following calls are important
                        df.ChannelPut("", mac.data(), mac.size());
                        df.ChannelPut("AAD", iv.data(), iv.size());
                        df.ChannelPut("", enc.data(), enc.size());

                        // If the object throws, it will most likely occur
                        //  during ChannelMessageEnd()
                        df.ChannelMessageEnd("AAD");
                        df.ChannelMessageEnd("");

                        // If the object does not throw, here's the only
                        //  opportunity to check the data's integrity
                        bool b = false;
                        b      = df.GetLastResult();
                        assert(true == b);

                        CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                        CryptoPP::ArraySink    sink(block, block.size());
                        plain.TransferTo(sink);

                        plaintext = block;
                    }
                    catch (CryptoPP::InvalidArgument& e)
                    {
                        std::cerr << "Caught InvalidArgument..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
                    {
                        // Pushing PDATA before ADATA results in:
                        //  "GMC/CryptoPP::CryptoPP::AES: Update was called before State_IVSet"
                        std::cerr << "Caught BadState..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
                    {
                        std::cerr << "Caught HashVerificationFailed..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    }

                    return plaintext;
                }
            } // namespace gcm

            namespace eax
            {
                template <typename F>
                CryptoPP::SecByteBlock encrypt(CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int&                     TAG_SIZE) {
                    CryptoPP::SecByteBlock ciphertext;
                    try
                    {
                        typename CryptoPP::EAX<F>::Encryption e;
                        e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                        // Not required for CryptoPP::GCM mode (but required for CCM mode)
                        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

                        CryptoPP::ByteQueue cipherq;

                        CryptoPP::AuthenticatedEncryptionFilter ef(e, new CryptoPP::Redirector(cipherq), false,
                                                                   TAG_SIZE);

                        // AuthenticatedEncryptionFilter::ChannelPut
                        //  defines two channels: "" (empty) and "AAD"
                        //   channel "" is encrypted and authenticated
                        //   channel "AAD" is authenticated
                        ef.ChannelPut("AAD", iv.data(), iv.size());
                        ef.ChannelMessageEnd("AAD");

                        // Authenticated data *must* be pushed before
                        //  Confidential/Authenticated data. Otherwise
                        //  we must catch the BadState exception
                        ef.ChannelPut("", plaintext.data(), plaintext.size());
                        ef.ChannelMessageEnd("");

                        CryptoPP::SecByteBlock block(cipherq.MaxRetrievable());
                        CryptoPP::ArraySink    sink(block, block.size());
                        cipherq.TransferTo(sink);

                        ciphertext = block;
                    }
                    catch (CryptoPP::BufferedTransformation::NoChannelSupport& e)
                    {
                        // The tag must go in to the default channel:
                        //  "unknown: this object doesn't support multiple channels"
                        std::cerr << "Caught NoChannelSupport..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
                    {
                        // Pushing PDATA before ADATA results in:
                        //  "GMC/CryptoPP::CryptoPP::AES: Update was called before State_IVSet"
                        std::cerr << "Caught BadState..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::InvalidArgument& e)
                    {
                        std::cerr << "Caught InvalidArgument..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    }
                    return ciphertext;
                }

                template <typename F>
                CryptoPP::SecByteBlock decrypt(CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key,
                                               CryptoPP::SecByteBlock& iv, const int&                      TAG_SIZE) {
                    CryptoPP::SecByteBlock plaintext;
                    try
                    {
                        typename CryptoPP::EAX<F>::Decryption d;
                        d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

                        // Break the cipher text out into it's
                        //  components: Encrypted Data and MAC Value
                        //CryptoPP::SecByteBlock mac = cipher.substr(cipher.length() - TAG_SIZE);

                        CryptoPP::SecByteBlock enc(ciphertext.data(), ciphertext.size() - TAG_SIZE);
                        CryptoPP::SecByteBlock mac(ciphertext.data() + ciphertext.size() - TAG_SIZE, TAG_SIZE);

                        CryptoPP::ByteQueue plain;

                        CryptoPP::AuthenticatedDecryptionFilter df(d, new CryptoPP::Redirector(plain),
                                                                   CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN
                                                                   | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                                                   TAG_SIZE);

                        // The order of the following calls are important
                        df.ChannelPut("", mac.data(), mac.size());
                        df.ChannelPut("AAD", iv.data(), iv.size());
                        df.ChannelPut("", enc.data(), enc.size());

                        // If the object throws, it will most likely occur
                        //  during ChannelMessageEnd()
                        df.ChannelMessageEnd("AAD");
                        df.ChannelMessageEnd("");

                        // If the object does not throw, here's the only
                        //  opportunity to check the data's integrity
                        bool b = false;
                        b      = df.GetLastResult();
                        assert(true == b);

                        CryptoPP::SecByteBlock block(plain.MaxRetrievable());
                        CryptoPP::ArraySink    sink(block, block.size());
                        plain.TransferTo(sink);

                        plaintext = block;
                    }
                    catch (CryptoPP::InvalidArgument& e)
                    {
                        std::cerr << "Caught InvalidArgument..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
                    {
                        // Pushing PDATA before ADATA results in:
                        //  "GMC/CryptoPP::CryptoPP::AES: Update was called before State_IVSet"
                        std::cerr << "Caught BadState..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
                    {
                        std::cerr << "Caught HashVerificationFailed..." << std::endl;
                        std::cerr << e.what() << std::endl;
                        std::cerr << std::endl;
                    }

                    return plaintext;
                }
            } // namespace gcm
        }     // namespace aead
    }         // namespace cipher
}             // namespace serin

//CryptoPP::HIGHT
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::LEA
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::DES_EDE3
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::DES_EDE2
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::IDEA
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SPECK128
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SPECK64
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SIMECK32
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SIMECK64
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SIMON128
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SIMON64
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SEED
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SKIPJACK
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::RC6
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::Camellia
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SHACAL2
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::AES
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::Twofish
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::Blowfish
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::Serpent
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::CHAM128
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::CHAM64
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::ARIA
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::MARS
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SHARK
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::Square
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::GOST
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SAFER_K
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::SAFER_SK
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::CAST128
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::CAST256
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::ThreeWay
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::TEA
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::XTEA
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::RC2>
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::RC5>
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::DES_XEX3>
template CryptoPP::SecByteBlock serin::cipher::ctr::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::ctr::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& ctr);
template CryptoPP::SecByteBlock serin::cipher::cbc::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cbc::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::xts::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::ofb::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cts::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
template CryptoPP::SecByteBlock serin::cipher::cfb::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

//CryptoPP::HIGHT
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::HIGHT>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::LEA
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::LEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::DES_EDE3
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::DES_EDE3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::DES_EDE2
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::DES_EDE2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::IDEA
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::IDEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SPECK128
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SPECK128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SPECK64
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SPECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SIMECK32
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SIMECK32>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SIMECK64
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SIMECK64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SIMON128
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SIMON128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SIMON64
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SIMON64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SEED
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SEED>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SKIPJACK
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SKIPJACK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::RC6
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::RC6>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::Camellia
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::Camellia>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SHACAL2
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SHACAL2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::AES
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::AES>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::Twofish
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::Twofish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::Blowfish
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::Blowfish>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::Serpent
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::Serpent>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::CHAM128
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::CHAM128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::CHAM64
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::CHAM64>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::ARIA
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::ARIA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::MARS
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::MARS>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SHARK
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SHARK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::Square
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::Square>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::GOST
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::GOST>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SAFER_K
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SAFER_K>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::SAFER_SK
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::SAFER_SK>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::CAST128
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::CAST128>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::CAST256
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::CAST256>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::ThreeWay
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::ThreeWay>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::TEA
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::TEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::XTEA
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::XTEA>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::RC2>
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::RC2>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::RC5>
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::RC5>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);

//CryptoPP::DES_XEX3>
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::gcm::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::encrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
template CryptoPP::SecByteBlock serin::cipher::aead::eax::decrypt<CryptoPP::DES_XEX3>(
    CryptoPP::SecByteBlock& ciphertext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, const int& TAG_SIZE);
