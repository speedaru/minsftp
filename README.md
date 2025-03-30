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

make sure you have these files inside lib\ folder:
- cryptlib.lib
- libcrypto_static.lib
- libssh2.lib
- libssl_static.lib 
