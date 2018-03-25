#include <QVault.h>
#include <CryptoContext.h>
#include <AesCipher.h>

#include <QString>
#include <QtTest>
#include <QDir>
#include <QDateTime>

class QVaultLibTest : public QObject
{
    Q_OBJECT

public:
    QVaultLibTest();
    ~QVaultLibTest();

private Q_SLOTS:
    void testNewVaultInstanceIsLocked();
    void testVaultFilePathMethod();
    void testGetValueInLockedState();
    void testSetValueInLockedState();
    void testVaultUnlockingWithWrongPassword();
    void testVaultUnlockingWithCorrectPassword();
    void testSetGetValues();
    void testSetAndRemoveValue();
    void testLockUnlockSequence();
    void testChangePassword();

private:
    QString _vaultPath;
};

QVaultLibTest::QVaultLibTest()
{
    const QString vaultFileName = QString("vault%1").arg(QDateTime::currentMSecsSinceEpoch());
    _vaultPath = QDir::temp().filePath(vaultFileName);
    qDebug() << "Vault filepath" << _vaultPath;

    bool success = QVault::create(_vaultPath, "password");

    QVERIFY(success);
    QVERIFY(QFile(_vaultPath).size() > 0);
}

QVaultLibTest::~QVaultLibTest()
{
    QFile(_vaultPath).remove();
}

void QVaultLibTest::testNewVaultInstanceIsLocked()
{
    QVault vault(_vaultPath);
    QVERIFY(vault.isLocked());
}

void QVaultLibTest::testVaultFilePathMethod()
{
    QVault vault(_vaultPath);
    QCOMPARE(_vaultPath, vault.filepath());
}

void QVaultLibTest::testGetValueInLockedState()
{
    QVault vault(_vaultPath);
    bool ok;
    vault.getValue("key", &ok);
    QVERIFY(!ok);
}

void QVaultLibTest::testSetValueInLockedState()
{
    QVault vault(_vaultPath);
    bool success = vault.setValue("key", "value");
    QVERIFY(!success);
}

void QVaultLibTest::testVaultUnlockingWithWrongPassword()
{
    QVault vault(_vaultPath);
    bool success = vault.unlock("wrong password");
    QVERIFY(!success);
}

void QVaultLibTest::testVaultUnlockingWithCorrectPassword()
{
    QVault vault(_vaultPath);
    bool success = vault.unlock("password");
    QVERIFY(success);
}

void QVaultLibTest::testSetGetValues()
{
    QVault vault(_vaultPath);
    bool ok = vault.unlock("password");
    QVERIFY(ok);

    ok = vault.setValue("stringKey", QString("Some string"));
    QVERIFY(ok);
    ok = vault.setValue("intKey", 123);
    QVERIFY(ok);
    ok = vault.setValue("doubleKey", 3.14);
    QVERIFY(ok);

    int intValue = vault.getValue("intKey", &ok).toInt();
    QVERIFY(ok);
    QCOMPARE(intValue, 123);
    double doubleValue = vault.getValue("doubleKey", &ok).toDouble();
    QVERIFY(ok);
    QCOMPARE(doubleValue, 3.14);
    QString stringValue = vault.getValue("stringKey", &ok).toString();
    QVERIFY(ok);
    QCOMPARE(stringValue, "Some string");
}

void QVaultLibTest::testSetAndRemoveValue()
{
    QVault vault(_vaultPath);
    bool ok = vault.unlock("password");
    QVERIFY(ok);

    ok = vault.setValue("stringKey", QString("Some string"));
    QVERIFY(ok);
    ok = vault.setValue("intKey", 123);
    QVERIFY(ok);
    ok = vault.setValue("doubleKey", 3.14);
    QVERIFY(ok);

    ok = vault.removeValue("intKey");
    QVERIFY(ok);

    vault.getValue("intKey", &ok);
    QVERIFY(!ok);
    double doubleValue = vault.getValue("doubleKey", &ok).toDouble();
    QVERIFY(ok);
    QCOMPARE(doubleValue, 3.14);
    QString stringValue = vault.getValue("stringKey", &ok).toString();
    QVERIFY(ok);
    QCOMPARE(stringValue, "Some string");
}

void QVaultLibTest::testLockUnlockSequence()
{
    QVault vault(_vaultPath);
    bool ok = vault.unlock("password");
    QVERIFY(ok);

    ok = vault.clear();
    QVERIFY(ok);

    ok = vault.setValue("stringKey", QString("Some string"));
    QVERIFY(ok);

    vault.lock();
    QVERIFY(vault.isLocked());

    ok = vault.unlock("password");
    QVERIFY(ok);    
    QVERIFY(!vault.isLocked());

    int c = 100;
    while (c-- > 0) {
        vault.setValue("stringKey", QString("Some string"));
        vault.getValue("stringKey", &ok);
    }
    QString stringValue = vault.getValue("stringKey", &ok).toString();
    QVERIFY(ok);
    QCOMPARE(stringValue, "Some string");
}

void QVaultLibTest::testChangePassword()
{
    QString newVaultPath = _vaultPath + "_newPassword";
    bool ok = QFile(_vaultPath).copy(newVaultPath);
    QVERIFY(ok);

    QVault vault(newVaultPath);
    ok = vault.unlock("password");
    QVERIFY(ok);

    ok = vault.changePassword("new password");
    QVERIFY(ok);

    vault.lock();
    QVERIFY(vault.isLocked());

    ok = vault.unlock("new password");
    QVERIFY(ok);
    QVERIFY(!vault.isLocked());

    QFile(newVaultPath).remove();
}

QTEST_APPLESS_MAIN(QVaultLibTest)

#include "QVaultLibTests.moc"
