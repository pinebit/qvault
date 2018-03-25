#ifndef AESCIPHER_H
#define AESCIPHER_H

#include <QByteArray>

struct evp_cipher_ctx_st;

class AesCipher
{
public:
    AesCipher(const QByteArray &key, const QByteArray &iv);
    virtual ~AesCipher();

    QByteArray encrypt(const QByteArray& data);
    QByteArray decrypt(const QByteArray& data);

private:
    evp_cipher_ctx_st *_ctx;
    QByteArray _key;
    QByteArray _iv;
};

#endif // AESCIPHER_H
