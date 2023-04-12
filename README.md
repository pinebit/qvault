# QVault

> QVault is the encrypted key-value store library for Qt/C++.

The library is using OpenSSL for data encryption, specifically:
- PKCS5_PBKDF2_HMAC_SHA1 for key derivation,
- EVP_aes_256_cbc cipher for encryption,
- HMAC w. EVP_sha256 for digest.

The library has been built with Qt5 (OpenSource) and C++11.

## Goals

The goal was to make the implementation the most secure, rather than super performant.
A typical usage of such a store is to persist user credentials, encryption keys and other
sensistive data (of small amount) on the disk that are accessed by "unlocking" the store with a password.
When store is locked, no "open text" data remains in memory, including AES encryption keys.

## Usage

For the very first time, a user shall create a vault instance protected with a password:

```cpp
#include <QVault.h>

bool success = QVault::create("~/vault.bin", "mystrongpassword");
```

After the store is created, the user must unlock it to being able set/get values:

```cpp
QVault vault("~/vault.bin");
bool success = vault.unlock("mystrongpassword");

// set a key-value pair
vault.setValue("btc-wallet-key", btcWalletKey);

// get a value for the key
bool ok;
QString btcWalletKey = vault.getValue("btc-walled-key", &ok).toString();
```

To change the password at any time (the store must be unlocked, of course):
```cpp
bool success = vault.changePassword("mynewstrongpassword");
```

After you finished accessing the values, just lock() it to ensure no encryption keys or any data left in memory:
```cpp
vault.lock()
```

## Notes

* All methods are synchronous and all write operations will commit all changes to the disk.
* You cannot enumerate keys by design, because getting all keys are insecure operation.
* You will need OpenSSL dev libs to be installed in your environment for this code to be built.

## License

GPLv3
