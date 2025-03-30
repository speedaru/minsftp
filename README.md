# minsftp

`minsftp` is a C++ wrapper around [libssh2](https://www.libssh2.org/) that simplifies SFTP file and directory operations like reading, writing, copying, moving, and deleting — all with a clean object-oriented interface.

## 🚀 Features

- Easy initialization with password or public key authentication
- Read/write files as `std::vector<uint8_t>`
- Copy, move, and delete remote files/directories

## 🔧 Usage

### Example

```cpp
#include "minsftp.h"

Client client("user@192.168.1.10:22");
a_password auth = { "mypassword" };
minsftp sftp(client, AUTH_PASSWORD, &auth);

if (sftp.Init() == RES_OK) {
    FILE_DATA data;
    sftp.ReadBytes("/remote/path/file.txt", data);
    // do something with data...

    sftp.WriteBytes("/remote/path/backup.txt", data);

    sftp.SftpMove("/remote/path/backup.txt", "/remote/path/newname.txt");
    sftp.Shutdown();
}
```

## 📦 Requirements

- libss2
- OpenSSL (for libssh2)
- Windows (WinSock2) or POSIX-compatible system
- C++ 17 or later

## 🛠 Build Instructions

make sure you have the static version of these lib files for example in a lib\ folder:
- cryptlib.lib
- libcrypto.lib
- libssh2.lib
- libssl.lib 

### you can get cryptlib.lib by building it from:
- [cryptopp](https://github.com/weidai11/cryptopp)

get cryptopp release 8.9
build it using visual studio
after building it will be in packages\openssl_x64-windows-static\lib

### you can get libcrypto.lib and libssl.lib by building openssl from source or using vcpkg:
- [openssl](https://github.com/openssl/openssl)
- [vcpkg](https://github.com/microsoft/vcpkg)

run bootstrap-vcpkg
then run: vcpkg install openssl
it will build openssl for you
then you can find libcrypto.lib and libssl.lib in buildtrees\openssl\x64-windows-rel

### you can get libssh2.lib using the same methods as above:
- [libssh2](https://github.com/libssh2/libssh2)
- [vcpkg](https://github.com/microsoft/vcpkg)

for vcpkg run: vcpkg install libssh2:x64-windows-static
it will build libssh2 for you
you can find libssh2.lib in packages\libssh2_x64-windows-static\lib

you don't need to add these files to the linker because minsftp.h will import them using #pragma comment
