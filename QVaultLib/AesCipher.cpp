#include "AesCipher.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>

const int AES_KEY_SIZE = 16;
const int IV_SIZE = 16;

typedef const unsigned char* cpbytes;

AesCipher::AesCipher(const QByteArray &key, const QByteArray &iv)
    : _ctx(EVP_CIPHER_CTX_new())
    , _key(key)
    , _iv(iv)
{
    Q_ASSERT(_ctx);
    Q_ASSERT(key.size() == AES_KEY_SIZE);
    Q_ASSERT(iv.size() == IV_SIZE);
}

AesCipher::~AesCipher()
{
    EVP_CIPHER_CTX_free(_ctx);
}

QByteArray AesCipher::encrypt(const QByteArray &data)
{
    Q_ASSERT(data.size() > 0);

    QByteArray buffer(data.size() + AES_KEY_SIZE, '\0');
    unsigned char *dest = (unsigned char*)buffer.data();

    if (1 == EVP_EncryptInit_ex(_ctx, EVP_aes_256_cbc(), NULL, (cpbytes)_key.data(), (cpbytes)_iv.data())) {
        int len = 0;
        if (1 == EVP_EncryptUpdate(_ctx, dest, &len, (cpbytes)data.data(), data.size())) {
            int buffer_size = len;
            if (1 == EVP_EncryptFinal_ex(_ctx, dest + len, &len)) {
                buffer_size += len;
                return buffer.left(buffer_size);
            }
        }
    }

    return QByteArray();
}

QByteArray AesCipher::decrypt(const QByteArray &data)
{
    Q_ASSERT(data.size() > 0);

    QByteArray buffer(data.size(), '\0');
    unsigned char *dest = (unsigned char*)buffer.data();
    int outlen = 0, tmplen = 0;

    if (1 == EVP_DecryptInit_ex(_ctx, EVP_aes_256_cbc(), NULL, (cpbytes)_key.data(), (cpbytes)_iv.data())) {
        if (1 == EVP_DecryptUpdate(_ctx, dest, &outlen, (cpbytes)data.data(), data.length())) {
            if (1 == EVP_DecryptFinal_ex(_ctx, dest + outlen, &tmplen)) {
                outlen += tmplen;
                return buffer.left(outlen);
            }
        }
    }

    return QByteArray();
}
