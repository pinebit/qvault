#ifndef CRYPTOCONTEXT_H
#define CRYPTOCONTEXT_H

#include <QByteArray>

class CryptoContext
{
public:
    explicit CryptoContext(const QByteArray &aesKey,
                           const QByteArray &iv,
                           const QByteArray &macKey,
                           const QByteArray &salt,
                           int iterations);
    virtual ~CryptoContext();

    void wipe();

    QByteArray secretKey() const;
    QByteArray aesKey() const;
    QByteArray iv() const;
    QByteArray macKey() const;
    QByteArray salt() const;
    int iterations() const;

private:
    QByteArray _aesKey;
    QByteArray _iv;
    QByteArray _macKey;
    QByteArray _salt;
    int _iterations;
};

#endif // CRYPTOCONTEXT_H
