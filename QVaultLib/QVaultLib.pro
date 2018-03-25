#----------------------------------------------------
# QVaultLib - the encrypted key-value store library.
#
# The solution is based on OpenSSL, so make sure
# you added OpenSSL headers and libraries.
#
#----------------------------------------------------

TEMPLATE = lib
TARGET = QVaultLib
QT -= gui
CONFIG += staticlib
DESTDIR = ../dist

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
        QVault.cpp \
    CryptoContext.cpp \
    AesCipher.cpp

HEADERS += \
        QVault.h \
    CryptoContext.h \
    AesCipher.h
unix {
    target.path = /usr/lib
    INSTALLS += target
}

DISTFILES += \
    QVaultLib.pri
