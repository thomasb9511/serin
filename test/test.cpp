// serin

#include <iostream>
#include <sstream>

#include <cryptopp/aes.h>
#include <cryptopp/aria.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cham.h>
#include <cryptopp/des.h>
#include <cryptopp/gost.h>
#include <cryptopp/hight.h>
#include <cryptopp/idea.h>
#include <cryptopp/lea.h>
#include <cryptopp/mars.h>
#include <cryptopp/rc2.h>
#include <cryptopp/rc5.h>
#include <cryptopp/rc6.h>
#include <cryptopp/safer.h>
#include <cryptopp/secblock.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/shark.h>
#include <cryptopp/simon.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/square.h>
#include <cryptopp/tea.h>
#include <cryptopp/twofish.h>
#include <cryptopp/simeck.h>
#include <cryptopp/speck.h>

#include "serin.h"
#include "cipher.h"
#include "transform.h"
#include "rng.h"

struct blk
{
    char key_bit;
    char iv_bit;
    char str_bit;
};

static blk       key_arry[] = {{0x00, 0x00, 0x00}, {0x00, 0x00, 0x01},};
std::vector<blk> key_vec(key_arry, key_arry + std::size(key_arry));

template <typename T>
void c(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::ctr::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CTR," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void b(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::cbc::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CBC," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void a(blk& ae) {
    if (T::BLOCKSIZE != 16) { return; }

    const serin::secure_string key(T::DEFAULT_KEYLENGTH * 2, ae.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, ae.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, ae.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::xts::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "XTS," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void d(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + T::BLOCKSIZE / 2, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::cts::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CTS," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void e(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::ofb::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "OFB," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void f(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);
    CryptoPP::SecByteBlock     aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock     aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::cfb::encrypt<T>(pt, aes_key, aes_iv);

    std::cout << "CFB," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void g(blk& a) {
    if (T::BLOCKSIZE != 16) { return; }

    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::aead::gcm::encrypt<T>(pt, aes_key, aes_iv, T::BLOCKSIZE);

    std::cout << "GCM," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

template <typename T>
void h(blk& a) {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, a.key_bit);
    const serin::secure_string iv(T::BLOCKSIZE, a.iv_bit);
    const serin::secure_string str(T::BLOCKSIZE + 0, a.str_bit);

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

    CryptoPP::SecByteBlock aes_data = serin::cipher::aead::eax::encrypt<T>(pt, aes_key, aes_iv, T::BLOCKSIZE);

    std::cout << "EAX," << typeid(T).name() << ',' << serin::transform::hex::to(pt) << ',' <<
        serin::transform::hex::to(aes_data) << ',' << serin::transform::hex::to(aes_key) << ',' <<
        serin::transform::hex::to(aes_iv) << std::endl;
}

// CryptoPP::SecByteBlock pt = BLACKBOX::prompt<CryptoPP::SHA3_512, CryptoPP::BLAKE2b>('x');

template <typename T, typename X>
void super_enc() {
    const serin::secure_string key(T::DEFAULT_KEYLENGTH, 0x00);
    const serin::secure_string iv(T::BLOCKSIZE, 0xFF);
    const serin::secure_string key2(X::DEFAULT_KEYLENGTH, 0xFF);
    const serin::secure_string iv2(X::BLOCKSIZE, 0x00);

    const serin::secure_string pl(T::BLOCKSIZE + 8, 0xA5);

    CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(pl.data()), pl.size());

    CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    CryptoPP::SecByteBlock aes_ctr(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());
    CryptoPP::SecByteBlock aes_key2(reinterpret_cast<const CryptoPP::byte*>(key2.data()), key2.size());
    CryptoPP::SecByteBlock aes_ctr2(reinterpret_cast<const CryptoPP::byte*>(iv2.data()), iv2.size());

    const serin::secure_string p(pt.size(), 0xFF);

    CryptoPP::SecByteBlock p_key(reinterpret_cast<const CryptoPP::byte*>(p.data()), p.size());

    CryptoPP::SecByteBlock pt2 = serin::transform::logical::xo(p_key, pt);

    CryptoPP::SecByteBlock pk = serin::cipher::ctr::encrypt<T>(pt2, aes_key, aes_ctr) + aes_ctr;

    CryptoPP::SecByteBlock pk2 = serin::cipher::ctr::encrypt<X>(p_key, aes_key2, aes_ctr2) + aes_ctr2;

    pt2 = pk + pk2;

    std::cout << "CTR," << typeid(T).name() << ',' << typeid(X).name() << ',' << serin::transform::hex::to(pt2) << ','
        << serin::transform::hex::to(aes_key) << ',' << serin::transform::hex::to(aes_key2) << "\n\n";
}

void vanity() {
    std::string key = serin::rng::X917::randstrng(CryptoPP::AES::MAX_KEYLENGTH);

    key = serin::transform::hex::to(key) + "h";

    CryptoPP::Integer x(key.c_str());

    CryptoPP::Integer y("8c2b6143c494e74628498b77f4a2bfccb9152f047bdfdd864c86728a781f9768h");

    x = x % y;

#pragma omp parallel
    {
        size_t i = 0;

        CryptoPP::SecByteBlock aes_iv = serin::rng::X917::randblock(CryptoPP::AES::BLOCKSIZE);

        bool looptrig = true;

        while (looptrig)
        {
            std::ostringstream stream;
            stream << std::hex << x;
            std::string s = stream.str();

            s = serin::transform::hex::from(s);

            s.insert(s.begin(), CryptoPP::AES::MAX_KEYLENGTH - s.size(), 0x00);

            const serin::secure_string ptstr("\x01\x23\x45\x67\x89\xab\xcd\xef", 8);

            CryptoPP::SecByteBlock ptx(reinterpret_cast<const CryptoPP::byte*>(ptstr.data()), ptstr.size());

            CryptoPP::SecByteBlock aes_key(reinterpret_cast<const CryptoPP::byte*>(s.data()), s.size());

            CryptoPP::SecByteBlock aes_data = serin::cipher::ctr::encrypt<CryptoPP::AES>(ptx, aes_key, aes_iv);

            s = serin::transform::hex::to(aes_data);

            std::string s2 = s.substr(0, i + 1);

            size_t n = std::count(s2.begin(), s2.end(), '0');

            if (n > i)
            {
                i = n;
#pragma omp critical
                std::cout << "ctr\t" << n << '\t' << serin::transform::hex::to(aes_data) << '\t' <<
                    serin::transform::hex::to(aes_key) << '\t' << serin::transform::hex::to(aes_iv) << std::endl;
                if (n == s.length()) { looptrig = false; }
            }
            ++x;
        }
    }
}

int main() {
    for (auto& i : key_vec)
    {
        a<CryptoPP::HIGHT>(i);
        b<CryptoPP::HIGHT>(i);
        c<CryptoPP::HIGHT>(i);
        d<CryptoPP::HIGHT>(i);
        e<CryptoPP::HIGHT>(i);
        f<CryptoPP::HIGHT>(i);
        g<CryptoPP::HIGHT>(i);
        h<CryptoPP::HIGHT>(i);

        a<CryptoPP::LEA>(i);
        b<CryptoPP::LEA>(i);
        c<CryptoPP::LEA>(i);
        d<CryptoPP::LEA>(i);
        e<CryptoPP::LEA>(i);
        f<CryptoPP::LEA>(i);
        g<CryptoPP::LEA>(i);
        h<CryptoPP::LEA>(i);

        a<CryptoPP::DES_EDE3>(i);
        b<CryptoPP::DES_EDE3>(i);
        c<CryptoPP::DES_EDE3>(i);
        d<CryptoPP::DES_EDE3>(i);
        e<CryptoPP::DES_EDE3>(i);
        f<CryptoPP::DES_EDE3>(i);
        g<CryptoPP::DES_EDE3>(i);
        h<CryptoPP::DES_EDE3>(i);

        a<CryptoPP::DES_EDE2>(i);
        b<CryptoPP::DES_EDE2>(i);
        c<CryptoPP::DES_EDE2>(i);
        d<CryptoPP::DES_EDE2>(i);
        e<CryptoPP::DES_EDE2>(i);
        f<CryptoPP::DES_EDE2>(i);
        g<CryptoPP::DES_EDE2>(i);
        h<CryptoPP::DES_EDE2>(i);

        a<CryptoPP::IDEA>(i);
        b<CryptoPP::IDEA>(i);
        c<CryptoPP::IDEA>(i);
        d<CryptoPP::IDEA>(i);
        e<CryptoPP::IDEA>(i);
        f<CryptoPP::IDEA>(i);
        g<CryptoPP::IDEA>(i);
        h<CryptoPP::IDEA>(i);

        a<CryptoPP::SPECK128>(i);
        b<CryptoPP::SPECK128>(i);
        c<CryptoPP::SPECK128>(i);
        d<CryptoPP::SPECK128>(i);
        e<CryptoPP::SPECK128>(i);
        f<CryptoPP::SPECK128>(i);
        g<CryptoPP::SPECK128>(i);
        h<CryptoPP::SPECK128>(i);

        a<CryptoPP::SPECK64>(i);
        b<CryptoPP::SPECK64>(i);
        c<CryptoPP::SPECK64>(i);
        d<CryptoPP::SPECK64>(i);
        e<CryptoPP::SPECK64>(i);
        f<CryptoPP::SPECK64>(i);
        g<CryptoPP::SPECK64>(i);
        h<CryptoPP::SPECK64>(i);

        a<CryptoPP::SIMECK32>(i);
        b<CryptoPP::SIMECK32>(i);
        c<CryptoPP::SIMECK32>(i);
        d<CryptoPP::SIMECK32>(i);
        e<CryptoPP::SIMECK32>(i);
        f<CryptoPP::SIMECK32>(i);
        g<CryptoPP::SIMECK32>(i);
        h<CryptoPP::SIMECK32>(i);

        a<CryptoPP::SIMECK64>(i);
        b<CryptoPP::SIMECK64>(i);
        c<CryptoPP::SIMECK64>(i);
        d<CryptoPP::SIMECK64>(i);
        e<CryptoPP::SIMECK64>(i);
        f<CryptoPP::SIMECK64>(i);
        g<CryptoPP::SIMECK64>(i);
        h<CryptoPP::SIMECK64>(i);

        a<CryptoPP::SIMON128>(i);
        b<CryptoPP::SIMON128>(i);
        c<CryptoPP::SIMON128>(i);
        d<CryptoPP::SIMON128>(i);
        e<CryptoPP::SIMON128>(i);
        f<CryptoPP::SIMON128>(i);
        g<CryptoPP::SIMON128>(i);
        h<CryptoPP::SIMON128>(i);

        a<CryptoPP::SIMON64>(i);
        b<CryptoPP::SIMON64>(i);
        c<CryptoPP::SIMON64>(i);
        d<CryptoPP::SIMON64>(i);
        e<CryptoPP::SIMON64>(i);
        f<CryptoPP::SIMON64>(i);
        g<CryptoPP::SIMON64>(i);
        h<CryptoPP::SIMON64>(i);

        a<CryptoPP::SEED>(i);
        b<CryptoPP::SEED>(i);
        c<CryptoPP::SEED>(i);
        d<CryptoPP::SEED>(i);
        e<CryptoPP::SEED>(i);
        f<CryptoPP::SEED>(i);
        g<CryptoPP::SEED>(i);
        h<CryptoPP::SEED>(i);

        a<CryptoPP::SKIPJACK>(i);
        b<CryptoPP::SKIPJACK>(i);
        c<CryptoPP::SKIPJACK>(i);
        d<CryptoPP::SKIPJACK>(i);
        e<CryptoPP::SKIPJACK>(i);
        f<CryptoPP::SKIPJACK>(i);
        g<CryptoPP::SKIPJACK>(i);
        h<CryptoPP::SKIPJACK>(i);

        a<CryptoPP::RC6>(i);
        b<CryptoPP::RC6>(i);
        c<CryptoPP::RC6>(i);
        d<CryptoPP::RC6>(i);
        e<CryptoPP::RC6>(i);
        f<CryptoPP::RC6>(i);
        g<CryptoPP::RC6>(i);
        h<CryptoPP::RC6>(i);

        a<CryptoPP::Camellia>(i);
        b<CryptoPP::Camellia>(i);
        c<CryptoPP::Camellia>(i);
        d<CryptoPP::Camellia>(i);
        e<CryptoPP::Camellia>(i);
        f<CryptoPP::Camellia>(i);
        g<CryptoPP::Camellia>(i);
        h<CryptoPP::Camellia>(i);

        a<CryptoPP::SHACAL2>(i);
        b<CryptoPP::SHACAL2>(i);
        c<CryptoPP::SHACAL2>(i);
        d<CryptoPP::SHACAL2>(i);
        e<CryptoPP::SHACAL2>(i);
        f<CryptoPP::SHACAL2>(i);
        g<CryptoPP::SHACAL2>(i);
        h<CryptoPP::SHACAL2>(i);

        a<CryptoPP::AES>(i);
        b<CryptoPP::AES>(i);
        c<CryptoPP::AES>(i);
        d<CryptoPP::AES>(i);
        e<CryptoPP::AES>(i);
        f<CryptoPP::AES>(i);
        g<CryptoPP::AES>(i);
        h<CryptoPP::AES>(i);

        a<CryptoPP::Twofish>(i);
        b<CryptoPP::Twofish>(i);
        c<CryptoPP::Twofish>(i);
        d<CryptoPP::Twofish>(i);
        e<CryptoPP::Twofish>(i);
        f<CryptoPP::Twofish>(i);
        g<CryptoPP::Twofish>(i);
        h<CryptoPP::Twofish>(i);

        a<CryptoPP::Blowfish>(i);
        b<CryptoPP::Blowfish>(i);
        c<CryptoPP::Blowfish>(i);
        d<CryptoPP::Blowfish>(i);
        e<CryptoPP::Blowfish>(i);
        f<CryptoPP::Blowfish>(i);
        g<CryptoPP::Blowfish>(i);
        h<CryptoPP::Blowfish>(i);

        a<CryptoPP::Serpent>(i);
        b<CryptoPP::Serpent>(i);
        c<CryptoPP::Serpent>(i);
        d<CryptoPP::Serpent>(i);
        e<CryptoPP::Serpent>(i);
        f<CryptoPP::Serpent>(i);
        g<CryptoPP::Serpent>(i);
        h<CryptoPP::Serpent>(i);

        a<CryptoPP::CHAM128>(i);
        b<CryptoPP::CHAM128>(i);
        c<CryptoPP::CHAM128>(i);
        d<CryptoPP::CHAM128>(i);
        e<CryptoPP::CHAM128>(i);
        f<CryptoPP::CHAM128>(i);
        g<CryptoPP::CHAM128>(i);
        h<CryptoPP::CHAM128>(i);

        a<CryptoPP::CHAM64>(i);
        b<CryptoPP::CHAM64>(i);
        c<CryptoPP::CHAM64>(i);
        d<CryptoPP::CHAM64>(i);
        e<CryptoPP::CHAM64>(i);
        f<CryptoPP::CHAM64>(i);
        g<CryptoPP::CHAM64>(i);
        h<CryptoPP::CHAM64>(i);

        a<CryptoPP::ARIA>(i);
        b<CryptoPP::ARIA>(i);
        c<CryptoPP::ARIA>(i);
        d<CryptoPP::ARIA>(i);
        e<CryptoPP::ARIA>(i);
        f<CryptoPP::ARIA>(i);
        g<CryptoPP::ARIA>(i);
        h<CryptoPP::ARIA>(i);

        a<CryptoPP::MARS>(i);
        b<CryptoPP::MARS>(i);
        c<CryptoPP::MARS>(i);
        d<CryptoPP::MARS>(i);
        e<CryptoPP::MARS>(i);
        f<CryptoPP::MARS>(i);
        g<CryptoPP::MARS>(i);
        h<CryptoPP::MARS>(i);

        a<CryptoPP::SHARK>(i);
        b<CryptoPP::SHARK>(i);
        c<CryptoPP::SHARK>(i);
        d<CryptoPP::SHARK>(i);
        e<CryptoPP::SHARK>(i);
        f<CryptoPP::SHARK>(i);
        g<CryptoPP::SHARK>(i);
        h<CryptoPP::SHARK>(i);

        a<CryptoPP::Square>(i);
        b<CryptoPP::Square>(i);
        c<CryptoPP::Square>(i);
        d<CryptoPP::Square>(i);
        e<CryptoPP::Square>(i);
        f<CryptoPP::Square>(i);
        g<CryptoPP::Square>(i);
        h<CryptoPP::Square>(i);

        a<CryptoPP::GOST>(i);
        b<CryptoPP::GOST>(i);
        c<CryptoPP::GOST>(i);
        d<CryptoPP::GOST>(i);
        e<CryptoPP::GOST>(i);
        f<CryptoPP::GOST>(i);
        g<CryptoPP::GOST>(i);
        h<CryptoPP::GOST>(i);

        a<CryptoPP::SAFER_K>(i);
        b<CryptoPP::SAFER_K>(i);
        c<CryptoPP::SAFER_K>(i);
        d<CryptoPP::SAFER_K>(i);
        e<CryptoPP::SAFER_K>(i);
        f<CryptoPP::SAFER_K>(i);
        g<CryptoPP::SAFER_K>(i);
        h<CryptoPP::SAFER_K>(i);

        a<CryptoPP::SAFER_SK>(i);
        b<CryptoPP::SAFER_SK>(i);
        c<CryptoPP::SAFER_SK>(i);
        d<CryptoPP::SAFER_SK>(i);
        e<CryptoPP::SAFER_SK>(i);
        f<CryptoPP::SAFER_SK>(i);
        g<CryptoPP::SAFER_SK>(i);
        h<CryptoPP::SAFER_SK>(i);

        a<CryptoPP::CAST128>(i);
        b<CryptoPP::CAST128>(i);
        c<CryptoPP::CAST128>(i);
        d<CryptoPP::CAST128>(i);
        e<CryptoPP::CAST128>(i);
        f<CryptoPP::CAST128>(i);
        g<CryptoPP::CAST128>(i);
        h<CryptoPP::CAST128>(i);

        a<CryptoPP::CAST256>(i);
        b<CryptoPP::CAST256>(i);
        c<CryptoPP::CAST256>(i);
        d<CryptoPP::CAST256>(i);
        e<CryptoPP::CAST256>(i);
        f<CryptoPP::CAST256>(i);
        g<CryptoPP::CAST256>(i);
        h<CryptoPP::CAST256>(i);

        a<CryptoPP::ThreeWay>(i);
        b<CryptoPP::ThreeWay>(i);
        c<CryptoPP::ThreeWay>(i);
        d<CryptoPP::ThreeWay>(i);
        e<CryptoPP::ThreeWay>(i);
        f<CryptoPP::ThreeWay>(i);
        g<CryptoPP::ThreeWay>(i);
        h<CryptoPP::ThreeWay>(i);

        a<CryptoPP::TEA>(i);
        b<CryptoPP::TEA>(i);
        c<CryptoPP::TEA>(i);
        d<CryptoPP::TEA>(i);
        e<CryptoPP::TEA>(i);
        f<CryptoPP::TEA>(i);
        g<CryptoPP::TEA>(i);
        h<CryptoPP::TEA>(i);

        a<CryptoPP::XTEA>(i);
        b<CryptoPP::XTEA>(i);
        c<CryptoPP::XTEA>(i);
        d<CryptoPP::XTEA>(i);
        e<CryptoPP::XTEA>(i);
        f<CryptoPP::XTEA>(i);
        g<CryptoPP::XTEA>(i);
        h<CryptoPP::XTEA>(i);

        a<CryptoPP::RC2>(i);
        b<CryptoPP::RC2>(i);
        c<CryptoPP::RC2>(i);
        d<CryptoPP::RC2>(i);
        e<CryptoPP::RC2>(i);
        f<CryptoPP::RC2>(i);
        g<CryptoPP::RC2>(i);
        h<CryptoPP::RC2>(i);

        a<CryptoPP::RC5>(i);
        b<CryptoPP::RC5>(i);
        c<CryptoPP::RC5>(i);
        d<CryptoPP::RC5>(i);
        e<CryptoPP::RC5>(i);
        f<CryptoPP::RC5>(i);
        g<CryptoPP::RC5>(i);
        h<CryptoPP::RC5>(i);

        a<CryptoPP::DES_XEX3>(i);
        b<CryptoPP::DES_XEX3>(i);
        c<CryptoPP::DES_XEX3>(i);
        d<CryptoPP::DES_XEX3>(i);
        e<CryptoPP::DES_XEX3>(i);
        f<CryptoPP::DES_XEX3>(i);
        g<CryptoPP::DES_XEX3>(i);
        h<CryptoPP::DES_XEX3>(i);
    }

    std::cout << "\n\n\n\n";

    super_enc<CryptoPP::HIGHT, CryptoPP::LEA>();
    super_enc<CryptoPP::HIGHT, CryptoPP::DES_EDE3>();
    super_enc<CryptoPP::HIGHT, CryptoPP::DES_EDE2>();
    super_enc<CryptoPP::HIGHT, CryptoPP::IDEA>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SPECK128>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SPECK64>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SIMON128>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SIMON64>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SEED>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::HIGHT, CryptoPP::RC6>();
    super_enc<CryptoPP::HIGHT, CryptoPP::Camellia>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::HIGHT, CryptoPP::AES>();
    super_enc<CryptoPP::HIGHT, CryptoPP::Twofish>();
    super_enc<CryptoPP::HIGHT, CryptoPP::Blowfish>();
    super_enc<CryptoPP::HIGHT, CryptoPP::Serpent>();
    super_enc<CryptoPP::HIGHT, CryptoPP::CHAM128>();
    super_enc<CryptoPP::HIGHT, CryptoPP::CHAM64>();
    super_enc<CryptoPP::HIGHT, CryptoPP::ARIA>();
    super_enc<CryptoPP::HIGHT, CryptoPP::MARS>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SHARK>();
    super_enc<CryptoPP::HIGHT, CryptoPP::Square>();
    super_enc<CryptoPP::HIGHT, CryptoPP::GOST>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::HIGHT, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::HIGHT, CryptoPP::CAST128>();
    super_enc<CryptoPP::HIGHT, CryptoPP::CAST256>();
    super_enc<CryptoPP::HIGHT, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::HIGHT, CryptoPP::TEA>();
    super_enc<CryptoPP::HIGHT, CryptoPP::XTEA>();
    super_enc<CryptoPP::HIGHT, CryptoPP::RC2>();
    super_enc<CryptoPP::HIGHT, CryptoPP::RC5>();
    super_enc<CryptoPP::HIGHT, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::LEA, CryptoPP::DES_EDE3>();
    super_enc<CryptoPP::LEA, CryptoPP::DES_EDE2>();
    super_enc<CryptoPP::LEA, CryptoPP::IDEA>();
    super_enc<CryptoPP::LEA, CryptoPP::SPECK128>();
    super_enc<CryptoPP::LEA, CryptoPP::SPECK64>();
    super_enc<CryptoPP::LEA, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::LEA, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::LEA, CryptoPP::SIMON128>();
    super_enc<CryptoPP::LEA, CryptoPP::SIMON64>();
    super_enc<CryptoPP::LEA, CryptoPP::SEED>();
    super_enc<CryptoPP::LEA, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::LEA, CryptoPP::RC6>();
    super_enc<CryptoPP::LEA, CryptoPP::Camellia>();
    super_enc<CryptoPP::LEA, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::LEA, CryptoPP::AES>();
    super_enc<CryptoPP::LEA, CryptoPP::Twofish>();
    super_enc<CryptoPP::LEA, CryptoPP::Blowfish>();
    super_enc<CryptoPP::LEA, CryptoPP::Serpent>();
    super_enc<CryptoPP::LEA, CryptoPP::CHAM128>();
    super_enc<CryptoPP::LEA, CryptoPP::CHAM64>();
    super_enc<CryptoPP::LEA, CryptoPP::ARIA>();
    super_enc<CryptoPP::LEA, CryptoPP::MARS>();
    super_enc<CryptoPP::LEA, CryptoPP::SHARK>();
    super_enc<CryptoPP::LEA, CryptoPP::Square>();
    super_enc<CryptoPP::LEA, CryptoPP::GOST>();
    super_enc<CryptoPP::LEA, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::LEA, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::LEA, CryptoPP::CAST128>();
    super_enc<CryptoPP::LEA, CryptoPP::CAST256>();
    super_enc<CryptoPP::LEA, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::LEA, CryptoPP::TEA>();
    super_enc<CryptoPP::LEA, CryptoPP::XTEA>();
    super_enc<CryptoPP::LEA, CryptoPP::RC2>();
    super_enc<CryptoPP::LEA, CryptoPP::RC5>();
    super_enc<CryptoPP::LEA, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::DES_EDE2>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::IDEA>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SPECK128>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SPECK64>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SIMON128>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SIMON64>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SEED>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::RC6>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::Camellia>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::AES>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::Twofish>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::Blowfish>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::Serpent>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::CHAM128>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::CHAM64>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::ARIA>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::MARS>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SHARK>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::Square>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::GOST>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::CAST128>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::CAST256>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::TEA>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::XTEA>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::RC2>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::RC5>();
    super_enc<CryptoPP::DES_EDE3, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::IDEA>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SPECK128>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SPECK64>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SIMON128>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SIMON64>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SEED>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::RC6>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::Camellia>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::AES>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::Twofish>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::Blowfish>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::Serpent>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::CHAM128>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::CHAM64>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::ARIA>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::MARS>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SHARK>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::Square>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::GOST>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::CAST128>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::CAST256>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::TEA>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::XTEA>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::RC2>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::RC5>();
    super_enc<CryptoPP::DES_EDE2, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::IDEA, CryptoPP::SPECK128>();
    super_enc<CryptoPP::IDEA, CryptoPP::SPECK64>();
    super_enc<CryptoPP::IDEA, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::IDEA, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::IDEA, CryptoPP::SIMON128>();
    super_enc<CryptoPP::IDEA, CryptoPP::SIMON64>();
    super_enc<CryptoPP::IDEA, CryptoPP::SEED>();
    super_enc<CryptoPP::IDEA, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::IDEA, CryptoPP::RC6>();
    super_enc<CryptoPP::IDEA, CryptoPP::Camellia>();
    super_enc<CryptoPP::IDEA, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::IDEA, CryptoPP::AES>();
    super_enc<CryptoPP::IDEA, CryptoPP::Twofish>();
    super_enc<CryptoPP::IDEA, CryptoPP::Blowfish>();
    super_enc<CryptoPP::IDEA, CryptoPP::Serpent>();
    super_enc<CryptoPP::IDEA, CryptoPP::CHAM128>();
    super_enc<CryptoPP::IDEA, CryptoPP::CHAM64>();
    super_enc<CryptoPP::IDEA, CryptoPP::ARIA>();
    super_enc<CryptoPP::IDEA, CryptoPP::MARS>();
    super_enc<CryptoPP::IDEA, CryptoPP::SHARK>();
    super_enc<CryptoPP::IDEA, CryptoPP::Square>();
    super_enc<CryptoPP::IDEA, CryptoPP::GOST>();
    super_enc<CryptoPP::IDEA, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::IDEA, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::IDEA, CryptoPP::CAST128>();
    super_enc<CryptoPP::IDEA, CryptoPP::CAST256>();
    super_enc<CryptoPP::IDEA, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::IDEA, CryptoPP::TEA>();
    super_enc<CryptoPP::IDEA, CryptoPP::XTEA>();
    super_enc<CryptoPP::IDEA, CryptoPP::RC2>();
    super_enc<CryptoPP::IDEA, CryptoPP::RC5>();
    super_enc<CryptoPP::IDEA, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SPECK64>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SIMON128>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SIMON64>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SEED>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SPECK128, CryptoPP::RC6>();
    super_enc<CryptoPP::SPECK128, CryptoPP::Camellia>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SPECK128, CryptoPP::AES>();
    super_enc<CryptoPP::SPECK128, CryptoPP::Twofish>();
    super_enc<CryptoPP::SPECK128, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SPECK128, CryptoPP::Serpent>();
    super_enc<CryptoPP::SPECK128, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SPECK128, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SPECK128, CryptoPP::ARIA>();
    super_enc<CryptoPP::SPECK128, CryptoPP::MARS>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SHARK>();
    super_enc<CryptoPP::SPECK128, CryptoPP::Square>();
    super_enc<CryptoPP::SPECK128, CryptoPP::GOST>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SPECK128, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SPECK128, CryptoPP::CAST128>();
    super_enc<CryptoPP::SPECK128, CryptoPP::CAST256>();
    super_enc<CryptoPP::SPECK128, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SPECK128, CryptoPP::TEA>();
    super_enc<CryptoPP::SPECK128, CryptoPP::XTEA>();
    super_enc<CryptoPP::SPECK128, CryptoPP::RC2>();
    super_enc<CryptoPP::SPECK128, CryptoPP::RC5>();
    super_enc<CryptoPP::SPECK128, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SIMECK32>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SIMON128>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SIMON64>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SEED>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SPECK64, CryptoPP::RC6>();
    super_enc<CryptoPP::SPECK64, CryptoPP::Camellia>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SPECK64, CryptoPP::AES>();
    super_enc<CryptoPP::SPECK64, CryptoPP::Twofish>();
    super_enc<CryptoPP::SPECK64, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SPECK64, CryptoPP::Serpent>();
    super_enc<CryptoPP::SPECK64, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SPECK64, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SPECK64, CryptoPP::ARIA>();
    super_enc<CryptoPP::SPECK64, CryptoPP::MARS>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SHARK>();
    super_enc<CryptoPP::SPECK64, CryptoPP::Square>();
    super_enc<CryptoPP::SPECK64, CryptoPP::GOST>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SPECK64, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SPECK64, CryptoPP::CAST128>();
    super_enc<CryptoPP::SPECK64, CryptoPP::CAST256>();
    super_enc<CryptoPP::SPECK64, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SPECK64, CryptoPP::TEA>();
    super_enc<CryptoPP::SPECK64, CryptoPP::XTEA>();
    super_enc<CryptoPP::SPECK64, CryptoPP::RC2>();
    super_enc<CryptoPP::SPECK64, CryptoPP::RC5>();
    super_enc<CryptoPP::SPECK64, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SIMECK64>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SIMON128>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SIMON64>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SEED>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::RC6>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::Camellia>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::AES>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::Twofish>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::Serpent>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::ARIA>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::MARS>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SHARK>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::Square>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::GOST>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::CAST128>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::CAST256>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::TEA>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::XTEA>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::RC2>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::RC5>();
    super_enc<CryptoPP::SIMECK32, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SIMON128>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SIMON64>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SEED>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::RC6>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::Camellia>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::AES>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::Twofish>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::Serpent>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::ARIA>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::MARS>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SHARK>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::Square>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::GOST>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::CAST128>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::CAST256>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::TEA>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::XTEA>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::RC2>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::RC5>();
    super_enc<CryptoPP::SIMECK64, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SIMON64>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SEED>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SIMON128, CryptoPP::RC6>();
    super_enc<CryptoPP::SIMON128, CryptoPP::Camellia>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SIMON128, CryptoPP::AES>();
    super_enc<CryptoPP::SIMON128, CryptoPP::Twofish>();
    super_enc<CryptoPP::SIMON128, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SIMON128, CryptoPP::Serpent>();
    super_enc<CryptoPP::SIMON128, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SIMON128, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SIMON128, CryptoPP::ARIA>();
    super_enc<CryptoPP::SIMON128, CryptoPP::MARS>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SHARK>();
    super_enc<CryptoPP::SIMON128, CryptoPP::Square>();
    super_enc<CryptoPP::SIMON128, CryptoPP::GOST>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SIMON128, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SIMON128, CryptoPP::CAST128>();
    super_enc<CryptoPP::SIMON128, CryptoPP::CAST256>();
    super_enc<CryptoPP::SIMON128, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SIMON128, CryptoPP::TEA>();
    super_enc<CryptoPP::SIMON128, CryptoPP::XTEA>();
    super_enc<CryptoPP::SIMON128, CryptoPP::RC2>();
    super_enc<CryptoPP::SIMON128, CryptoPP::RC5>();
    super_enc<CryptoPP::SIMON128, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SEED>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SIMON64, CryptoPP::RC6>();
    super_enc<CryptoPP::SIMON64, CryptoPP::Camellia>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SIMON64, CryptoPP::AES>();
    super_enc<CryptoPP::SIMON64, CryptoPP::Twofish>();
    super_enc<CryptoPP::SIMON64, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SIMON64, CryptoPP::Serpent>();
    super_enc<CryptoPP::SIMON64, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SIMON64, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SIMON64, CryptoPP::ARIA>();
    super_enc<CryptoPP::SIMON64, CryptoPP::MARS>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SHARK>();
    super_enc<CryptoPP::SIMON64, CryptoPP::Square>();
    super_enc<CryptoPP::SIMON64, CryptoPP::GOST>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SIMON64, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SIMON64, CryptoPP::CAST128>();
    super_enc<CryptoPP::SIMON64, CryptoPP::CAST256>();
    super_enc<CryptoPP::SIMON64, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SIMON64, CryptoPP::TEA>();
    super_enc<CryptoPP::SIMON64, CryptoPP::XTEA>();
    super_enc<CryptoPP::SIMON64, CryptoPP::RC2>();
    super_enc<CryptoPP::SIMON64, CryptoPP::RC5>();
    super_enc<CryptoPP::SIMON64, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SEED, CryptoPP::SKIPJACK>();
    super_enc<CryptoPP::SEED, CryptoPP::RC6>();
    super_enc<CryptoPP::SEED, CryptoPP::Camellia>();
    super_enc<CryptoPP::SEED, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SEED, CryptoPP::AES>();
    super_enc<CryptoPP::SEED, CryptoPP::Twofish>();
    super_enc<CryptoPP::SEED, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SEED, CryptoPP::Serpent>();
    super_enc<CryptoPP::SEED, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SEED, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SEED, CryptoPP::ARIA>();
    super_enc<CryptoPP::SEED, CryptoPP::MARS>();
    super_enc<CryptoPP::SEED, CryptoPP::SHARK>();
    super_enc<CryptoPP::SEED, CryptoPP::Square>();
    super_enc<CryptoPP::SEED, CryptoPP::GOST>();
    super_enc<CryptoPP::SEED, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SEED, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SEED, CryptoPP::CAST128>();
    super_enc<CryptoPP::SEED, CryptoPP::CAST256>();
    super_enc<CryptoPP::SEED, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SEED, CryptoPP::TEA>();
    super_enc<CryptoPP::SEED, CryptoPP::XTEA>();
    super_enc<CryptoPP::SEED, CryptoPP::RC2>();
    super_enc<CryptoPP::SEED, CryptoPP::RC5>();
    super_enc<CryptoPP::SEED, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::RC6>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::Camellia>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::AES>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::Twofish>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::Serpent>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::ARIA>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::MARS>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::SHARK>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::Square>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::GOST>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::CAST128>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::CAST256>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::TEA>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::XTEA>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::RC2>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::RC5>();
    super_enc<CryptoPP::SKIPJACK, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::RC6, CryptoPP::Camellia>();
    super_enc<CryptoPP::RC6, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::RC6, CryptoPP::AES>();
    super_enc<CryptoPP::RC6, CryptoPP::Twofish>();
    super_enc<CryptoPP::RC6, CryptoPP::Blowfish>();
    super_enc<CryptoPP::RC6, CryptoPP::Serpent>();
    super_enc<CryptoPP::RC6, CryptoPP::CHAM128>();
    super_enc<CryptoPP::RC6, CryptoPP::CHAM64>();
    super_enc<CryptoPP::RC6, CryptoPP::ARIA>();
    super_enc<CryptoPP::RC6, CryptoPP::MARS>();
    super_enc<CryptoPP::RC6, CryptoPP::SHARK>();
    super_enc<CryptoPP::RC6, CryptoPP::Square>();
    super_enc<CryptoPP::RC6, CryptoPP::GOST>();
    super_enc<CryptoPP::RC6, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::RC6, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::RC6, CryptoPP::CAST128>();
    super_enc<CryptoPP::RC6, CryptoPP::CAST256>();
    super_enc<CryptoPP::RC6, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::RC6, CryptoPP::TEA>();
    super_enc<CryptoPP::RC6, CryptoPP::XTEA>();
    super_enc<CryptoPP::RC6, CryptoPP::RC2>();
    super_enc<CryptoPP::RC6, CryptoPP::RC5>();
    super_enc<CryptoPP::RC6, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::Camellia, CryptoPP::SHACAL2>();
    super_enc<CryptoPP::Camellia, CryptoPP::AES>();
    super_enc<CryptoPP::Camellia, CryptoPP::Twofish>();
    super_enc<CryptoPP::Camellia, CryptoPP::Blowfish>();
    super_enc<CryptoPP::Camellia, CryptoPP::Serpent>();
    super_enc<CryptoPP::Camellia, CryptoPP::CHAM128>();
    super_enc<CryptoPP::Camellia, CryptoPP::CHAM64>();
    super_enc<CryptoPP::Camellia, CryptoPP::ARIA>();
    super_enc<CryptoPP::Camellia, CryptoPP::MARS>();
    super_enc<CryptoPP::Camellia, CryptoPP::SHARK>();
    super_enc<CryptoPP::Camellia, CryptoPP::Square>();
    super_enc<CryptoPP::Camellia, CryptoPP::GOST>();
    super_enc<CryptoPP::Camellia, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::Camellia, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::Camellia, CryptoPP::CAST128>();
    super_enc<CryptoPP::Camellia, CryptoPP::CAST256>();
    super_enc<CryptoPP::Camellia, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::Camellia, CryptoPP::TEA>();
    super_enc<CryptoPP::Camellia, CryptoPP::XTEA>();
    super_enc<CryptoPP::Camellia, CryptoPP::RC2>();
    super_enc<CryptoPP::Camellia, CryptoPP::RC5>();
    super_enc<CryptoPP::Camellia, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::AES>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::Twofish>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::Blowfish>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::Serpent>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::CHAM128>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::CHAM64>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::ARIA>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::MARS>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::SHARK>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::Square>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::GOST>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::CAST128>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::CAST256>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::TEA>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::XTEA>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::RC2>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::RC5>();
    super_enc<CryptoPP::SHACAL2, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::AES, CryptoPP::Twofish>();
    super_enc<CryptoPP::AES, CryptoPP::Blowfish>();
    super_enc<CryptoPP::AES, CryptoPP::Serpent>();
    super_enc<CryptoPP::AES, CryptoPP::CHAM128>();
    super_enc<CryptoPP::AES, CryptoPP::CHAM64>();
    super_enc<CryptoPP::AES, CryptoPP::ARIA>();
    super_enc<CryptoPP::AES, CryptoPP::MARS>();
    super_enc<CryptoPP::AES, CryptoPP::SHARK>();
    super_enc<CryptoPP::AES, CryptoPP::Square>();
    super_enc<CryptoPP::AES, CryptoPP::GOST>();
    super_enc<CryptoPP::AES, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::AES, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::AES, CryptoPP::CAST128>();
    super_enc<CryptoPP::AES, CryptoPP::CAST256>();
    super_enc<CryptoPP::AES, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::AES, CryptoPP::TEA>();
    super_enc<CryptoPP::AES, CryptoPP::XTEA>();
    super_enc<CryptoPP::AES, CryptoPP::RC2>();
    super_enc<CryptoPP::AES, CryptoPP::RC5>();
    super_enc<CryptoPP::AES, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::Twofish, CryptoPP::Blowfish>();
    super_enc<CryptoPP::Twofish, CryptoPP::Serpent>();
    super_enc<CryptoPP::Twofish, CryptoPP::CHAM128>();
    super_enc<CryptoPP::Twofish, CryptoPP::CHAM64>();
    super_enc<CryptoPP::Twofish, CryptoPP::ARIA>();
    super_enc<CryptoPP::Twofish, CryptoPP::MARS>();
    super_enc<CryptoPP::Twofish, CryptoPP::SHARK>();
    super_enc<CryptoPP::Twofish, CryptoPP::Square>();
    super_enc<CryptoPP::Twofish, CryptoPP::GOST>();
    super_enc<CryptoPP::Twofish, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::Twofish, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::Twofish, CryptoPP::CAST128>();
    super_enc<CryptoPP::Twofish, CryptoPP::CAST256>();
    super_enc<CryptoPP::Twofish, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::Twofish, CryptoPP::TEA>();
    super_enc<CryptoPP::Twofish, CryptoPP::XTEA>();
    super_enc<CryptoPP::Twofish, CryptoPP::RC2>();
    super_enc<CryptoPP::Twofish, CryptoPP::RC5>();
    super_enc<CryptoPP::Twofish, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::Blowfish, CryptoPP::Serpent>();
    super_enc<CryptoPP::Blowfish, CryptoPP::CHAM128>();
    super_enc<CryptoPP::Blowfish, CryptoPP::CHAM64>();
    super_enc<CryptoPP::Blowfish, CryptoPP::ARIA>();
    super_enc<CryptoPP::Blowfish, CryptoPP::MARS>();
    super_enc<CryptoPP::Blowfish, CryptoPP::SHARK>();
    super_enc<CryptoPP::Blowfish, CryptoPP::Square>();
    super_enc<CryptoPP::Blowfish, CryptoPP::GOST>();
    super_enc<CryptoPP::Blowfish, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::Blowfish, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::Blowfish, CryptoPP::CAST128>();
    super_enc<CryptoPP::Blowfish, CryptoPP::CAST256>();
    super_enc<CryptoPP::Blowfish, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::Blowfish, CryptoPP::TEA>();
    super_enc<CryptoPP::Blowfish, CryptoPP::XTEA>();
    super_enc<CryptoPP::Blowfish, CryptoPP::RC2>();
    super_enc<CryptoPP::Blowfish, CryptoPP::RC5>();
    super_enc<CryptoPP::Blowfish, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::Serpent, CryptoPP::CHAM128>();
    super_enc<CryptoPP::Serpent, CryptoPP::CHAM64>();
    super_enc<CryptoPP::Serpent, CryptoPP::ARIA>();
    super_enc<CryptoPP::Serpent, CryptoPP::MARS>();
    super_enc<CryptoPP::Serpent, CryptoPP::SHARK>();
    super_enc<CryptoPP::Serpent, CryptoPP::Square>();
    super_enc<CryptoPP::Serpent, CryptoPP::GOST>();
    super_enc<CryptoPP::Serpent, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::Serpent, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::Serpent, CryptoPP::CAST128>();
    super_enc<CryptoPP::Serpent, CryptoPP::CAST256>();
    super_enc<CryptoPP::Serpent, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::Serpent, CryptoPP::TEA>();
    super_enc<CryptoPP::Serpent, CryptoPP::XTEA>();
    super_enc<CryptoPP::Serpent, CryptoPP::RC2>();
    super_enc<CryptoPP::Serpent, CryptoPP::RC5>();
    super_enc<CryptoPP::Serpent, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::CHAM128, CryptoPP::CHAM64>();
    super_enc<CryptoPP::CHAM128, CryptoPP::ARIA>();
    super_enc<CryptoPP::CHAM128, CryptoPP::MARS>();
    super_enc<CryptoPP::CHAM128, CryptoPP::SHARK>();
    super_enc<CryptoPP::CHAM128, CryptoPP::Square>();
    super_enc<CryptoPP::CHAM128, CryptoPP::GOST>();
    super_enc<CryptoPP::CHAM128, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::CHAM128, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::CHAM128, CryptoPP::CAST128>();
    super_enc<CryptoPP::CHAM128, CryptoPP::CAST256>();
    super_enc<CryptoPP::CHAM128, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::CHAM128, CryptoPP::TEA>();
    super_enc<CryptoPP::CHAM128, CryptoPP::XTEA>();
    super_enc<CryptoPP::CHAM128, CryptoPP::RC2>();
    super_enc<CryptoPP::CHAM128, CryptoPP::RC5>();
    super_enc<CryptoPP::CHAM128, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::CHAM64, CryptoPP::ARIA>();
    super_enc<CryptoPP::CHAM64, CryptoPP::MARS>();
    super_enc<CryptoPP::CHAM64, CryptoPP::SHARK>();
    super_enc<CryptoPP::CHAM64, CryptoPP::Square>();
    super_enc<CryptoPP::CHAM64, CryptoPP::GOST>();
    super_enc<CryptoPP::CHAM64, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::CHAM64, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::CHAM64, CryptoPP::CAST128>();
    super_enc<CryptoPP::CHAM64, CryptoPP::CAST256>();
    super_enc<CryptoPP::CHAM64, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::CHAM64, CryptoPP::TEA>();
    super_enc<CryptoPP::CHAM64, CryptoPP::XTEA>();
    super_enc<CryptoPP::CHAM64, CryptoPP::RC2>();
    super_enc<CryptoPP::CHAM64, CryptoPP::RC5>();
    super_enc<CryptoPP::CHAM64, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::ARIA, CryptoPP::MARS>();
    super_enc<CryptoPP::ARIA, CryptoPP::SHARK>();
    super_enc<CryptoPP::ARIA, CryptoPP::Square>();
    super_enc<CryptoPP::ARIA, CryptoPP::GOST>();
    super_enc<CryptoPP::ARIA, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::ARIA, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::ARIA, CryptoPP::CAST128>();
    super_enc<CryptoPP::ARIA, CryptoPP::CAST256>();
    super_enc<CryptoPP::ARIA, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::ARIA, CryptoPP::TEA>();
    super_enc<CryptoPP::ARIA, CryptoPP::XTEA>();
    super_enc<CryptoPP::ARIA, CryptoPP::RC2>();
    super_enc<CryptoPP::ARIA, CryptoPP::RC5>();
    super_enc<CryptoPP::ARIA, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::MARS, CryptoPP::SHARK>();
    super_enc<CryptoPP::MARS, CryptoPP::Square>();
    super_enc<CryptoPP::MARS, CryptoPP::GOST>();
    super_enc<CryptoPP::MARS, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::MARS, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::MARS, CryptoPP::CAST128>();
    super_enc<CryptoPP::MARS, CryptoPP::CAST256>();
    super_enc<CryptoPP::MARS, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::MARS, CryptoPP::TEA>();
    super_enc<CryptoPP::MARS, CryptoPP::XTEA>();
    super_enc<CryptoPP::MARS, CryptoPP::RC2>();
    super_enc<CryptoPP::MARS, CryptoPP::RC5>();
    super_enc<CryptoPP::MARS, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SHARK, CryptoPP::Square>();
    super_enc<CryptoPP::SHARK, CryptoPP::GOST>();
    super_enc<CryptoPP::SHARK, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::SHARK, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SHARK, CryptoPP::CAST128>();
    super_enc<CryptoPP::SHARK, CryptoPP::CAST256>();
    super_enc<CryptoPP::SHARK, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SHARK, CryptoPP::TEA>();
    super_enc<CryptoPP::SHARK, CryptoPP::XTEA>();
    super_enc<CryptoPP::SHARK, CryptoPP::RC2>();
    super_enc<CryptoPP::SHARK, CryptoPP::RC5>();
    super_enc<CryptoPP::SHARK, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::Square, CryptoPP::GOST>();
    super_enc<CryptoPP::Square, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::Square, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::Square, CryptoPP::CAST128>();
    super_enc<CryptoPP::Square, CryptoPP::CAST256>();
    super_enc<CryptoPP::Square, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::Square, CryptoPP::TEA>();
    super_enc<CryptoPP::Square, CryptoPP::XTEA>();
    super_enc<CryptoPP::Square, CryptoPP::RC2>();
    super_enc<CryptoPP::Square, CryptoPP::RC5>();
    super_enc<CryptoPP::Square, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::GOST, CryptoPP::SAFER_K>();
    super_enc<CryptoPP::GOST, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::GOST, CryptoPP::CAST128>();
    super_enc<CryptoPP::GOST, CryptoPP::CAST256>();
    super_enc<CryptoPP::GOST, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::GOST, CryptoPP::TEA>();
    super_enc<CryptoPP::GOST, CryptoPP::XTEA>();
    super_enc<CryptoPP::GOST, CryptoPP::RC2>();
    super_enc<CryptoPP::GOST, CryptoPP::RC5>();
    super_enc<CryptoPP::GOST, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::SAFER_SK>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::CAST128>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::CAST256>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::TEA>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::XTEA>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::RC2>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::RC5>();
    super_enc<CryptoPP::SAFER_K, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::CAST128>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::CAST256>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::TEA>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::XTEA>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::RC2>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::RC5>();
    super_enc<CryptoPP::SAFER_SK, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::CAST128, CryptoPP::CAST256>();
    super_enc<CryptoPP::CAST128, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::CAST128, CryptoPP::TEA>();
    super_enc<CryptoPP::CAST128, CryptoPP::XTEA>();
    super_enc<CryptoPP::CAST128, CryptoPP::RC2>();
    super_enc<CryptoPP::CAST128, CryptoPP::RC5>();
    super_enc<CryptoPP::CAST128, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::CAST256, CryptoPP::ThreeWay>();
    super_enc<CryptoPP::CAST256, CryptoPP::TEA>();
    super_enc<CryptoPP::CAST256, CryptoPP::XTEA>();
    super_enc<CryptoPP::CAST256, CryptoPP::RC2>();
    super_enc<CryptoPP::CAST256, CryptoPP::RC5>();
    super_enc<CryptoPP::CAST256, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::ThreeWay, CryptoPP::TEA>();
    super_enc<CryptoPP::ThreeWay, CryptoPP::XTEA>();
    super_enc<CryptoPP::ThreeWay, CryptoPP::RC2>();
    super_enc<CryptoPP::ThreeWay, CryptoPP::RC5>();
    super_enc<CryptoPP::ThreeWay, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::TEA, CryptoPP::XTEA>();
    super_enc<CryptoPP::TEA, CryptoPP::RC2>();
    super_enc<CryptoPP::TEA, CryptoPP::RC5>();
    super_enc<CryptoPP::TEA, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::XTEA, CryptoPP::RC2>();
    super_enc<CryptoPP::XTEA, CryptoPP::RC5>();
    super_enc<CryptoPP::XTEA, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::RC2, CryptoPP::RC5>();
    super_enc<CryptoPP::RC2, CryptoPP::DES_XEX3>();
    super_enc<CryptoPP::RC5, CryptoPP::DES_XEX3>();

    vanity();
}
