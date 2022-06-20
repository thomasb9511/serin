// serin

#include <cryptopp/aes.h>
#include <cryptopp/aria.h>
#include <cryptopp/blake2.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cham.h>
#include <cryptopp/des.h>
#include <cryptopp/files.h>
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
#include <cryptopp/simeck.h>
#include <cryptopp/simon.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/speck.h>
#include <cryptopp/square.h>
#include <cryptopp/tea.h>
#include <cryptopp/twofish.h>

#include "cipher.h"
#include "hash.h"
#include "serin.h"
#include "transform.h"

struct blk
{
    char key_bit;
    char iv_bit;
    char str_bit;
};

std::vector<blk> key_vec;

template <typename T>
void output(std::string& filename, const std::string& mode_name, const std::string& algo_name) {
    std::string digest;
    digest = serin::hash::files::hash<T>(filename);

    std::cout << serin::transform::hex::to(digest) << " *" << filename << "\n";

    const std::string modefilename = mode_name + "/" + mode_name + ".BLAKE2b";

    std::ofstream myfile;
    myfile.open(modefilename, std::ios_base::binary | std::ios::app);

    myfile << serin::transform::hex::to(digest) << " *" << algo_name + ".csv" << "\n";

    myfile.close();

    const std::string file = "cipher_samples.BLAKE2b";

    std::ofstream fmyfile;
    fmyfile.open(file, std::ios_base::binary | std::ios::app);

    fmyfile << serin::transform::hex::to(digest) << " *" << filename << "\n";

    fmyfile.close();
}

template <typename T>
void c(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "CTR/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::ctr::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "CTR", algo_name);
}

template <typename T>
void b(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "CBC/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::cbc::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "CBC", algo_name);
}

template <typename T>
void a(const std::string& /*full_name*/, const std::string& algo_name) {
    if (T::BLOCKSIZE != 16) { return; }

    std::string filename = "XTS/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH * 2, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::xts::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "XTS", algo_name);
}

template <typename T>
void d(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "CTS/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::cts::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "CTS", algo_name);
}

template <typename T>
void e(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "OFB/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::ofb::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "OFB", algo_name);
}

template <typename T>
void f(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "CFB/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::cfb::encrypt<T>(pt, _key, _iv);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "CFB", algo_name);
}

template <typename T>
void g(const std::string& /*full_name*/, const std::string& algo_name) {
    if (T::BLOCKSIZE != 16) { return; }

    std::string filename = "GCM/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::aead::gcm::encrypt<T>(pt, _key, _iv, T::BLOCKSIZE);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "GCM", algo_name);
}

template <typename T>
void h(const std::string& /*full_name*/, const std::string& algo_name) {
    std::string filename = "EAX/" + algo_name + ".csv";

    std::ofstream myfile;
    myfile.open(filename);

    for (auto& i : key_vec)
    {
        const serin::secure_string key(T::DEFAULT_KEYLENGTH, i.key_bit);
        const serin::secure_string iv(T::BLOCKSIZE, i.iv_bit);
        const serin::secure_string str(T::BLOCKSIZE * 2, i.str_bit);

        CryptoPP::SecByteBlock _key(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
        CryptoPP::SecByteBlock _iv(reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());

        CryptoPP::SecByteBlock pt(reinterpret_cast<const CryptoPP::byte*>(str.data()), str.size());

        CryptoPP::SecByteBlock _data = serin::cipher::aead::eax::encrypt<T>(pt, _key, _iv, T::BLOCKSIZE);

        myfile << serin::transform::hex::to(pt) << ',' << serin::transform::hex::to(_data) << ',' <<
            serin::transform::hex::to(_key) << ',' << serin::transform::hex::to(_iv) << "\n";
    }

    myfile.close();

    output<CryptoPP::BLAKE2b>(filename, "EAX", algo_name);
}

int main() {
    char ar[] = {'0x00', '0x01', '0x02', '0x04', '0x08', '0x0F', '0x10', '0x11', '0x12', '0x14', '0x18', '0x1F', '0x20',
                 '0x21', '0x22', '0x23', '0x24', '0x28', '0x2F', '0x32', '0x33', '0x35', '0x3C', '0x40', '0x41', '0x42',
                 '0x44', '0x48', '0x4F', '0x53', '0x55', '0x56', '0x59', '0x5A', '0x5C', '0x65', '0x66', '0x69', '0x77',
                 '0x80', '0x81', '0x82', '0x84', '0x88', '0x8F', '0x95', '0x96', '0x99', '0xA5', '0xAA', '0xBB', '0xC3',
                 '0xC5', '0xCC', '0xDD', '0xDE', '0xED', '0xEE', '0xF0', '0xF1', '0xF2', '0xF4', '0xF8', '0xFF',};

    for (const char& x : ar)
    {
        for (const char& y : ar)
        {
            for (const char& z : ar)
            {
                blk temp = {x, y, z};
                key_vec.emplace_back(temp);
            }
        }
    }

    a<CryptoPP::AES>("CryptoPP::AES", "AES");
    a<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    a<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    a<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    a<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    a<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    a<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    a<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    a<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    a<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    a<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    a<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    a<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    a<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    a<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    a<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    a<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    a<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    a<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    a<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    a<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    a<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    a<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    a<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    a<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    a<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    a<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    a<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    a<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    a<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    a<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    a<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    a<CryptoPP::Square>("CryptoPP::Square", "Square");
    a<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    a<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    a<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    a<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    b<CryptoPP::AES>("CryptoPP::AES", "AES");
    b<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    b<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    b<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    b<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    b<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    b<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    b<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    b<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    b<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    b<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    b<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    b<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    b<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    b<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    b<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    b<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    b<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    b<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    b<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    b<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    b<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    b<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    b<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    b<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    b<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    b<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    b<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    b<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    b<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    b<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    b<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    b<CryptoPP::Square>("CryptoPP::Square", "Square");
    b<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    b<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    b<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    b<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    c<CryptoPP::AES>("CryptoPP::AES", "AES");
    c<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    c<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    c<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    c<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    c<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    c<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    c<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    c<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    c<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    c<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    c<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    c<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    c<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    c<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    c<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    c<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    c<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    c<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    c<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    c<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    c<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    c<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    c<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    c<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    c<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    c<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    c<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    c<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    c<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    c<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    c<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    c<CryptoPP::Square>("CryptoPP::Square", "Square");
    c<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    c<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    c<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    c<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    d<CryptoPP::AES>("CryptoPP::AES", "AES");
    d<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    d<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    d<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    d<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    d<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    d<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    d<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    d<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    d<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    d<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    d<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    d<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    d<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    d<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    d<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    d<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    d<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    d<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    d<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    d<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    d<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    d<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    d<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    d<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    d<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    d<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    d<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    d<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    d<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    d<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    d<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    d<CryptoPP::Square>("CryptoPP::Square", "Square");
    d<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    d<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    d<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    d<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    e<CryptoPP::AES>("CryptoPP::AES", "AES");
    e<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    e<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    e<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    e<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    e<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    e<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    e<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    e<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    e<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    e<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    e<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    e<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    e<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    e<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    e<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    e<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    e<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    e<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    e<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    e<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    e<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    e<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    e<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    e<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    e<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    e<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    e<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    e<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    e<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    e<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    e<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    e<CryptoPP::Square>("CryptoPP::Square", "Square");
    e<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    e<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    e<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    e<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    f<CryptoPP::AES>("CryptoPP::AES", "AES");
    f<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    f<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    f<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    f<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    f<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    f<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    f<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    f<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    f<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    f<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    f<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    f<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    f<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    f<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    f<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    f<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    f<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    f<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    f<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    f<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    f<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    f<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    f<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    f<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    f<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    f<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    f<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    f<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    f<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    f<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    f<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    f<CryptoPP::Square>("CryptoPP::Square", "Square");
    f<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    f<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    f<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    f<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    g<CryptoPP::AES>("CryptoPP::AES", "AES");
    g<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    g<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    g<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    g<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    g<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    g<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    g<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    g<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    g<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    g<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    g<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    g<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    g<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    g<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    g<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    g<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    g<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    g<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    g<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    g<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    g<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    g<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    g<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    g<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    g<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    g<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    g<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    g<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    g<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    g<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    g<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    g<CryptoPP::Square>("CryptoPP::Square", "Square");
    g<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    g<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    g<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    g<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
    h<CryptoPP::AES>("CryptoPP::AES", "AES");
    h<CryptoPP::ARIA>("CryptoPP::ARIA", "ARIA");
    h<CryptoPP::Blowfish>("CryptoPP::Blowfish", "Blowfish");
    h<CryptoPP::Camellia>("CryptoPP::Camellia", "Camellia");
    h<CryptoPP::CAST128>("CryptoPP::CAST128", "CAST128");
    h<CryptoPP::CAST256>("CryptoPP::CAST256", "CAST256");
    h<CryptoPP::CHAM128>("CryptoPP::CHAM128", "CHAM128");
    h<CryptoPP::CHAM64>("CryptoPP::CHAM64", "CHAM64");
    h<CryptoPP::DES_EDE2>("CryptoPP::DES_EDE2", "DES_EDE2");
    h<CryptoPP::DES_EDE3>("CryptoPP::DES_EDE3", "DES_EDE3");
    h<CryptoPP::DES_XEX3>("CryptoPP::DES_XEX3", "DES_XEX3");
    h<CryptoPP::GOST>("CryptoPP::GOST", "GOST");
    h<CryptoPP::HIGHT>("CryptoPP::HIGHT", "HIGHT");
    h<CryptoPP::IDEA>("CryptoPP::IDEA", "IDEA");
    h<CryptoPP::LEA>("CryptoPP::LEA", "LEA");
    h<CryptoPP::MARS>("CryptoPP::MARS", "MARS");
    h<CryptoPP::RC2>("CryptoPP::RC2", "RC2");
    h<CryptoPP::RC5>("CryptoPP::RC5", "RC5");
    h<CryptoPP::RC6>("CryptoPP::RC6", "RC6");
    h<CryptoPP::SAFER_K>("CryptoPP::SAFER_K", "SAFER_K");
    h<CryptoPP::SAFER_SK>("CryptoPP::SAFER_SK", "SAFER_SK");
    h<CryptoPP::SEED>("CryptoPP::SEED", "SEED");
    h<CryptoPP::Serpent>("CryptoPP::Serpent", "Serpent");
    h<CryptoPP::SHACAL2>("CryptoPP::SHACAL2", "SHACAL2");
    h<CryptoPP::SHARK>("CryptoPP::SHARK", "SHARK");
    h<CryptoPP::SIMECK32>("CryptoPP::SIMECK32", "SIMECK32");
    h<CryptoPP::SIMECK64>("CryptoPP::SIMECK64", "SIMECK64");
    h<CryptoPP::SIMON128>("CryptoPP::SIMON128", "SIMON128");
    h<CryptoPP::SIMON64>("CryptoPP::SIMON64", "SIMON64");
    h<CryptoPP::SKIPJACK>("CryptoPP::SKIPJACK", "SKIPJACK");
    h<CryptoPP::SPECK128>("CryptoPP::SPECK128", "SPECK128");
    h<CryptoPP::SPECK64>("CryptoPP::SPECK64", "SPECK64");
    h<CryptoPP::Square>("CryptoPP::Square", "Square");
    h<CryptoPP::TEA>("CryptoPP::TEA", "TEA");
    h<CryptoPP::ThreeWay>("CryptoPP::ThreeWay", "ThreeWay");
    h<CryptoPP::Twofish>("CryptoPP::Twofish", "Twofish");
    h<CryptoPP::XTEA>("CryptoPP::XTEA", "XTEA");
}
