#include <CryptoContext.h>
#include <AesCipher.h>
#include "QVault.h"

#include <QFile>
#include <QDebug>
#include <QElapsedTimer>
#include <QDataStream>

#include <openssl/rand.h>
#include <openssl/hmac.h>

const int MIN_ITERATIONS = 100;
const int BENCHMARK_ITERATIONS = 1000;
const quint64 TARGET_TIME_MILLIS = 50;
const int AES_KEY_SIZE = 16;
const int IV_SIZE = 16;
const int SALT_SIZE = 16;
const int HMAC_KEY_SIZE = 32;

QVault::QVault(const QString &filepath, QObject *parent)
    : QObject(parent)
    , _filepath(filepath)
    , _locked(true)
{
    Q_ASSERT(QFile(filepath).exists());
}

bool QVault::create(const QString &filepath, const QString &password)
{
    QFile vault(filepath);

    if (vault.exists()) {
        qDebug() << "Failed to create Vault because target file already exists" << filepath;
        return false;
    }

    if (password.isEmpty()) {
        qDebug() << "Failed to create Vault because password is empty";
        return false;
    }

    QByteArray salt = rand(SALT_SIZE);
    int iterations = estimateIterations(password, salt);
    QByteArray secretKey = generateSecretKey(password, iterations, salt);
    QByteArray macKey = secretKey.mid(AES_KEY_SIZE + IV_SIZE, HMAC_KEY_SIZE);

    QByteArray vaultData;
    QDataStream out(&vaultData, QIODevice::WriteOnly);
    out << salt
        << iterations
        << generateHmac(macKey, secretKey)
        << Records();

    if (!vault.open(QFile::WriteOnly)) {
        qDebug() << "Failed to open vault file for write" << filepath;
        return false;
    }
    vault.write(vaultData);
    vault.close();

    return true;
}

bool QVault::changePassword(const QString &newPassword)
{
    QByteArray salt = rand(SALT_SIZE);
    int iterations = estimateIterations(newPassword, salt);
    QByteArray secretKey = generateSecretKey(newPassword, iterations, salt);
    QByteArray aesKey = secretKey.left(AES_KEY_SIZE);
    QByteArray iv = secretKey.mid(AES_KEY_SIZE, IV_SIZE);
    QByteArray macKey = secretKey.mid(AES_KEY_SIZE + IV_SIZE, HMAC_KEY_SIZE);

    _context.reset(new CryptoContext(aesKey, iv, macKey, salt, iterations));
    _cipher.reset(new AesCipher(_context->aesKey(), _context->iv()));

    return save();
}

bool QVault::unlock(const QString &password)
{
    if (!_locked) {
        return true;
    }

    QFile vault(_filepath);
    if (!vault.open(QFile::ReadOnly)) {
        qDebug() << "Failed to open vault file to read" << _filepath;
        return false;
    }
    QByteArray vaultData = vault.readAll();
    vault.close();

    QDataStream in(vaultData);
    QByteArray salt, mac;
    int iterations;
    in >> salt >> iterations >> mac;

    QByteArray secretKey = generateSecretKey(password, iterations, salt);
    if (secretKey.size() == 0) {
        qDebug() << "Cannot unlock vault. Check password and vault file integrity.";
        return false;
    }

    if (mac != generateHmac(secretKey.right(HMAC_KEY_SIZE), secretKey)) {
        qDebug() << "Cannot unlock vault. Check password and vault file integrity.";
        return false;
    }

    _context.reset(new CryptoContext(secretKey.left(AES_KEY_SIZE),
                                     secretKey.mid(AES_KEY_SIZE, IV_SIZE),
                                     secretKey.right(HMAC_KEY_SIZE),
                                     salt,
                                     iterations));
    _cipher.reset(new AesCipher(_context->aesKey(), _context->iv()));

    in >> _records;
    _locked = false;

    return true;
}

void QVault::lock()
{
    _locked = true;
    _context.reset();
    _cipher.reset();
    _records.clear();
}

bool QVault::isLocked() const
{
    return _locked;
}

QString QVault::filepath() const
{
    return _filepath;
}

QVariant QVault::getValue(const QString &key, bool *ok)
{
    Q_ASSERT(ok);

    if (_locked) {
        qDebug() << "Cannot get values in locked state.";
        *ok = false;
        return QVariant();
    }

    QByteArray encryptedKey = _cipher->encrypt(key.toUtf8());
    if (!_records.contains(encryptedKey)) {
        qDebug() << "No such key found" << key;
        *ok = false;
        return QVariant();
    }

    QByteArray decryptedValue = _cipher->decrypt(_records.value(encryptedKey));
    QVariant value = deserializeVariant(decryptedValue);

    *ok = true;
    return value;
}

bool QVault::setValue(const QString &key, const QVariant &value)
{
    if (_locked) {
        qDebug() << "Cannot set values in locked state.";
        return false;
    }

    QByteArray encryptedKey = _cipher->encrypt(key.toUtf8());
    QByteArray encryptedValue = _cipher->encrypt(serializeVariant(value));

    _records[encryptedKey] = encryptedValue;

    return save();
}

bool QVault::removeValue(const QString &key)
{
    if (_locked) {
        qDebug() << "Cannot get values in locked state.";
        return false;
    }

    QByteArray encryptedKey = _cipher->encrypt(key.toUtf8());
    if (!_records.contains(encryptedKey)) {
        return true;
    }

    _records.remove(encryptedKey);

    return save();
}

bool QVault::clear()
{
    if (_locked) {
        qDebug() << "Cannot clear values in locked state.";
        return false;
    }

    _records.clear();
    return save();
}

QByteArray QVault::rand(int size)
{
    Q_ASSERT(size > 0);

    QByteArray buffer(size, '\0');

    if (RAND_bytes(reinterpret_cast<unsigned char*>(buffer.data()), buffer.size()) != 1) {
        qDebug() << "Failed to generate random bytes, size" << size;
    }

    return buffer;
}

int QVault::estimateIterations(const QString &password, const QByteArray &salt)
{
    QByteArray secretKey(AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE, '\0');
    QElapsedTimer timer;
    timer.start();

    if (PKCS5_PBKDF2_HMAC_SHA1(
                password.toUtf8().data(), password.size(),
                reinterpret_cast<const unsigned char*>(salt.data()), salt.size(), BENCHMARK_ITERATIONS,
                secretKey.size(), reinterpret_cast<unsigned char*>(secretKey.data())) != 1) {
        qDebug() << "Failed to benchmark iterations.";
        return MIN_ITERATIONS;
    }

    const qint64 milliseconds = timer.elapsed();
    const int iterations = (TARGET_TIME_MILLIS * BENCHMARK_ITERATIONS) / milliseconds;
    if (iterations < MIN_ITERATIONS) {
        return MIN_ITERATIONS;
    }

    return iterations;
}

QByteArray QVault::generateHmac(const QByteArray &macKey, const QByteArray &secretKey)
{
    QByteArray result(HMAC_KEY_SIZE, '\0');
    unsigned int length = HMAC_KEY_SIZE;

    HMAC(EVP_sha256(),
         reinterpret_cast<const unsigned char*>(macKey.data()),
         macKey.size(),
         reinterpret_cast<const unsigned char*>(secretKey.data()),
         secretKey.size(),
         reinterpret_cast<unsigned char*>(result.data()),
         &length);

    return result;
}

QByteArray QVault::serializeVariant(const QVariant &value)
{
    QByteArray serialized;
    QDataStream out(&serialized, QIODevice::WriteOnly);
    out << value;
    return serialized;
}

QVariant QVault::deserializeVariant(const QByteArray &data)
{
    QVariant value;
    QDataStream in(data);
    in >> value;
    return value;
}

QByteArray QVault::generateSecretKey(const QString &password, int iterations, const QByteArray &salt)
{
    QByteArray secretKey(AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE, '\0');

    if (PKCS5_PBKDF2_HMAC_SHA1(
                password.toUtf8().data(), password.size(),
                (const unsigned char*)salt.data(), salt.size(),
                iterations,
                secretKey.size(), reinterpret_cast<unsigned char*>(secretKey.data())) != 1) {
        qDebug() << "Failed to generate secret key.";
        return QByteArray();
    }

    return secretKey;
}

bool QVault::save() const
{
    QByteArray vaultData;
    QDataStream out(&vaultData, QIODevice::WriteOnly);
    out << _context->salt()
        << _context->iterations()
        << generateHmac(_context->macKey(), _context->secretKey())
        << _records;

    QFile vault(_filepath);
    vault.remove();

    if (!vault.open(QFile::WriteOnly)) {
        qDebug() << "Failed to open vault file for write" << _filepath;
        return false;
    }
    vault.write(vaultData);
    vault.close();

    return true;
}

