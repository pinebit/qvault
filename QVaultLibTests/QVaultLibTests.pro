#-------------------------------------------------
# QVaultLib unit tests
#-------------------------------------------------

QT += testlib
QT -= gui

TARGET = tst_qvaultlibtest
CONFIG   += console
CONFIG   -= app_bundle
TEMPLATE = app
DESTDIR = ../dist

DEFINES += QT_DEPRECATED_WARNINGS

include(../QVaultLib/QVaultLib.pri)

LIBS += -lssl -lcrypto

SOURCES += \
    QVaultLibTests.cpp

DEFINES += SRCDIR=\\\"$$PWD/\\\"
