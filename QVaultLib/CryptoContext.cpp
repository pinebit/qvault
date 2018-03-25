#include "CryptoContext.h"

CryptoContext::CryptoContext(const QByteArray &aesKey,
                             const QByteArray &iv,
                             const QByteArray &macKey,
                             const QByteArray &salt,
                             qint32 iterations)
    : _aesKey(aesKey)
    , _iv(iv)
    , _macKey(macKey)
    , _salt(salt)
    , _iterations(iterations)
{
}

CryptoContext::~CryptoContext()
{
    wipe();
}

QByteArray CryptoContext::secretKey() const
{
    return _aesKey + _iv + _macKey;
}

QByteArray CryptoContext::aesKey() const
{
    return _aesKey;
}

QByteArray CryptoContext::iv() const
{
    return _iv;
}

QByteArray CryptoContext::macKey() const
{
    return _macKey;
}

QByteArray CryptoContext::salt() const
{
    return _salt;
}

int CryptoContext::iterations() const
{
    return _iterations;
}

void CryptoContext::wipe()
{
    _aesKey.fill('\0');
    _iv.fill('\0');
    _macKey.fill('\0');
    _salt.fill('\0');
    _aesKey.clear();
    _iv.clear();
    _macKey.clear();
    _salt.clear();

    _iterations = 0;
}
