#ifndef QVAULT_H
#define QVAULT_H

#include <QObject>
#include <QVariant>
#include <QList>
#include <QByteArray>
#include <QScopedPointer>

class CryptoContext;
class AesCipher;

/**
 * @brief QVault is the encrypted key-value store.
 * @details
 * The store is encrypted with AES256 cipher (using OpenSSL library).
 * The encryption key is derived from user password and never kept in memory.
 * Values are accessed individually, not decrypting the whole store.
 * The solution is optimized for ultimate security, rather than performance.
 */
class QVault : public QObject
{
public:
    /**
     * @brief Initializes the instance.
     * @param filepath of the existing vault file.
     * @param parent - optional parent qobject.
     * @note No data is read or decrypted in this call. Initial state is locked.
     */
    explicit QVault(const QString &filepath, QObject *parent = nullptr);
    ~QVault() = default;

    /**
     * @brief Creates a new vault file protected with the specified password.
     * @param filepath of a vault file to be created.
     * @param password.
     * @return true if the new vault file is created.
     */
    static bool create(const QString &filepath, const QString &password);

    /**
     * @brief Changes the password by re-encrypting the entire vault.
     * @param newPassword.
     * @return true if operation was successful.
     * @note All work is done synchronously.
     */
    bool changePassword(const QString &newPassword);

    /**
     * @brief Unlocks vault by checking the password and preparing AES keys.
     * @param password.
     * @return false if password is wrong or vault is corrupted.
     * @note The password is not retained in-memory.
     */
    bool unlock(const QString &password);

    /**
     * @brief Locks vault by removing AES keys from memory.
     * @note In the locked state, no values can be written or read.
     */
    void lock();

    /**
     * @brief Gets the current locked state.
     * @return true if vault is locked.
     */
    bool isLocked() const;

    /**
     * @brief Gets vault file path specified in ctor.
     * @return Vault file path.
     */
    QString filepath() const;

    /**
     * @brief Gets a value idenfied by the specified key.
     * @param key to find the corresponding value.
     * @param ok - pointer to a boolean flag receiving operation status.
     * @return Value if found and decrypted, empty value if *ok == false.
     * @note Not allowed in locked state.
     */
    QVariant getValue(const QString &key, bool *ok);

    /**
     * @brief Sets a value identified by the specified key.
     * @param key that identifies the value.
     * @return true if the value is encrypted and written to vault file.
     * @note Not allowed in locked state.
     * @note Existing key will be overwritten.
     * @note All changes are written to disk synchronously.
     */
    bool setValue(const QString& key, const QVariant &value);

    /**
     * @brief Remove a value idenfied by the specified key.
     * @param key to find the corresponding value.
     * @return true if the key-value pair is removed.
     * @note Not allowed in locked state.
     * @note All changes are written to disk synchronously.
     */
    bool removeValue(const QString& key);

    /**
     * @brief Clears all values.
     * @return true if all value were removed.
     * @note All changes are written to disk synchronously.
     */
    bool clear();

private:
    Q_DISABLE_COPY(QVault)

private:
    // all keys and values are kept encrypted in memory.
    using Records = QMap<QByteArray, QByteArray>;

    static QByteArray rand(int size);
    static int estimateIterations(const QString &password, const QByteArray &salt);
    static QByteArray generateHmac(const QByteArray &macKey, const QByteArray &secretKey);
    static QByteArray serializeVariant(const QVariant &value);
    static QVariant deserializeVariant(const QByteArray &data);
    static QByteArray generateSecretKey(const QString &password, int iterations, const QByteArray &salt);

    bool save() const;

    QString _filepath;
    bool _locked;
    Records _records;
    QScopedPointer<AesCipher> _cipher;
    QScopedPointer<CryptoContext> _context;
};

#endif // QVAULT_H
