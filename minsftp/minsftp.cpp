#include "minsftp.h"


static void kbd_callback(const char* name, int name_len,
    const char* instruction, int instruction_len,
    int num_prompts,
    const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
    void** abstract)
{
    int i;
    size_t n;
    char buf[1024];
    (void)abstract;

    fprintf(stderr, "keyboard-interactive authentication.\n");

    fprintf(stderr, "authentication name: '");
    fwrite(name, 1, name_len, stderr);
    fprintf(stderr, "'\n");

    fprintf(stderr, "authentication instruction: '");
    fwrite(instruction, 1, instruction_len, stderr);
    fprintf(stderr, "'\n");

    fprintf(stderr, "number of prompts: %d\n\n", num_prompts);

    for (i = 0; i < num_prompts; i++) {
        fprintf(stderr, "prompt %d from server: '", i);
        fwrite(prompts[i].text, 1, prompts[i].length, stderr);
        fprintf(stderr, "'\n");

        fprintf(stderr, "please type response: ");
        fgets(buf, sizeof(buf), stdin);
        n = strlen(buf);
        while (n > 0 && strchr("\r\n", buf[n - 1]))
            n--;
        buf[n] = 0;

        responses[i].text = strdup(buf);
        responses[i].length = (unsigned int)n;

        fprintf(stderr, "response %d from user is '", i);
        fwrite(responses[i].text, 1, responses[i].length, stderr);
        fprintf(stderr, "'\n\n");

        // free the allocated memory when done using the response
        free(responses[i].text);
    }

    fprintf(stderr,
        "Done. Sending keyboard-interactive responses to server now.\n");
}


Client::Client(const char* format) {
    if (!IsValidFormat(format)) {
        fprintf(stderr, "invalid format: %s\n", format);
        return;
    }

    size_t hostAddrPos = strchr(format, '@') - format + 1;
    size_t portPos = strchr(format, ':') - format + 1;

    size_t userLen = hostAddrPos - 1;
    size_t hostAddrLen = portPos - hostAddrPos - 1;
    size_t portLen = strlen(format) - portPos;

    std::string fmt(format);
    std::string _user = fmt.substr(0, userLen);
    std::string _hostaddr = fmt.substr(hostAddrPos, hostAddrLen);
    std::string _port = fmt.substr(portPos, portLen);

    user = _user;
    hostaddr = inet_addr(_hostaddr.c_str());
    port = (u_short)std::stoi(_port.c_str());
}

bool Client::IsValidFormat(const char* format) {
    size_t userPos{ 0 };
    size_t hostAddrPos = NULL;
    size_t portPos = NULL;

    size_t len = strlen(format);
    for (int i = 0; i < len; i++) {
        char ch = format[i];
        if (ch == '@') {
            hostAddrPos = i;
        }
        else if (ch == ':') {
            portPos = i;
        }
    }

    return hostAddrPos != NULL && portPos != NULL;
}



minsftp::minsftp(Client _client, AUTH_TYPE _authType, void* authVal) {
    switch (_authType) {
    case AUTH_PASSWORD:
        password = *reinterpret_cast<a_password*>(authVal);
        break;
    case AUTH_PUBKEY:
        pubkey = *reinterpret_cast<a_pubkey*>(authVal);
        break;
    case AUTH_KEYBOARD:
        //empty
        break;
    }

    authType = _authType;
    client = _client;
}
minsftp::~minsftp() {
    Shutdown();
}


MINSFTP_RES minsftp::Init() {
    int i, auth_pw = 0;
    struct sockaddr_in sin;
    const char* fingerprint;
    char* userauthlist;
    int rc;
    
    WSADATA wsadata;
    
    // initialize Winsock library for windows
    rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if (rc) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
        return RES_WSA_FAILED;
    }
    
    // init libssh2 library
    rc = libssh2_init(0);
    if (rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return RES_INIT_LIBSSH2_FAILED;
    }
    
    /*
        * The application code is responsible for creating the socket
        * and establishing the connection
        */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket.\n");
        Shutdown();
        return RES_SOCKET_FAILED;
    }
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons(client.port);
    sin.sin_addr.s_addr = client.hostaddr;
    if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect.\n");
        Shutdown();
        return RES_CONNECTION_FAILED;
    }
    
    /* Create a session instance */
    session = libssh2_session_init();
    
    if (!session) {
        fprintf(stderr, "Could not initialize SSH session.\n");
        Shutdown();
        return RES_INIT_SSH_SESSION_FAILED;
    }
    
    /* Since we have set non-blocking, tell libssh2 we are blocking */
    libssh2_session_set_blocking(session, 1);
    
    
    /* ... start it up. This will trade welcome banners, exchange keys,
        * and setup crypto, compression, and MAC layers
        */
    rc = libssh2_session_handshake(session, sock);
    
    if (rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        Shutdown();
        return RES_SSH_SESSION_START_FAILED;
    }
    /* At this point we have not yet authenticated.  The first thing to do
        * is check the hostkey's fingerprint against our known hosts Your app
        * may have it hard coded, may go to a file, may present it to the
        * _user, that's your call
        */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    
    fprintf(stderr, "Fingerprint: ");
    for (i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    }
    fprintf(stderr, "\n");
    
    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(session, client.User(),
        (unsigned int)strlen(client.User()));

    if (userauthlist) {
        fprintf(stderr, "Authentication methods: %s\n", userauthlist);
        if (strstr(userauthlist, "password")) {
            auth_pw |= 1;
        }
        if (strstr(userauthlist, "keyboard-interactive")) {
            auth_pw |= 2;
        }
        if (strstr(userauthlist, "publickey")) {
            auth_pw |= 4;
        }
    
        switch (authType) {
        case AUTH_PASSWORD:
            // authenticate using password
            if (libssh2_userauth_password(session, client.User(), password.password)) {
                fprintf(stderr, "Authentication by password failed.\n");
                Shutdown();
                return RES_AUTH_PASS_FAILED;
            }
            break;
        case AUTH_KEYBOARD:
            // authenticate via keyboard-interactive
            if (libssh2_userauth_keyboard_interactive(session, client.User(), &kbd_callback)) {
                fprintf(stderr,
                    "Authentication by keyboard-interactive failed.\n");
                Shutdown();
                return RES_AUTH_KEYBOARD_FAILED;
            }
            else {
                fprintf(stderr,
                    "Authentication by keyboard-interactive succeeded.\n");
            }
            break;
        case AUTH_PUBKEY:
        {
            // authenticate using public key
            int res = libssh2_userauth_publickey_frommemory(session,
                client.User(), client.user.length(), // user
                NULL, NULL, // public key
                reinterpret_cast<const char*>(pubkey.privKeyData.data()), pubkey.privKeyData.size(), pubkey.passphrase); // priv key
            
            if (res) {
                fprintf(
                    stderr,
                    "authentication by public key failed.\nuser: %s userlen: %llu\npassphrase %s\n",
                    client.User(), client.user.length(), pubkey.passphrase);
                Shutdown();
                return RES_AUTH_PUBKEY_FAILED;
            }
            else {
                fprintf(stderr, "authentication by public key succeeded.\n");
            }
            break;
        }
        default:
            fprintf(stderr, "no supported authentication methods found.\n");
            Shutdown();
            return RES_NO_AUTH_METHODS;
            break;
        }
    }
    
    printf("libssh2_sftp_init().\n");
    
    sftp_session = libssh2_sftp_init(session);
    
    
    if (!sftp_session) {
        fprintf(stderr, "unable to init sftp session\n");
        Shutdown();
        return RES_INIT_SFTP_FAILED;
    }
    
    libssh2_initialized = true;
    return RES_OK;
}
void minsftp::Shutdown() {
    if (sftp_session) {
        libssh2_sftp_shutdown(sftp_session);
        sftp_session = nullptr;
    }

    if (session) {
        libssh2_session_disconnect(session, "normal Shutdown");
        libssh2_session_free(session);
        session = nullptr;  // nullify after free to prevent double cleanup
    }

    if (sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sock, 2);  // shutdown the socket for both reading and writing
#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        sock = LIBSSH2_INVALID_SOCKET;  // set to invalid socket after closing
    }

    // libssh2_exit() should be called only once per application lifetime
    // It might be best to ensure it's not called multiple times.
    if (libssh2_initialized) {  // check if libssh2 was libssh2_initialized
        libssh2_exit();
        libssh2_initialized = false;  // set the flag to prevent multiple calls
    }
}

FILE_DATA minsftp::ReadPrivateKeyFromFile(const std::string path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open private key file.");
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return data;
}

const char* minsftp::ResToStr(const MINSFTP_RES res) {
    switch (res) {
    case RES_OK:
        return "Operation succeeded.";
    case RES_FAILED:
        return "Operation failed.";
    case RES_WSA_FAILED:
        return "WSAStartup failed.";
    case RES_INIT_LIBSSH2_FAILED:
        return "Failed to initialize libssh2.";
    case RES_SOCKET_FAILED:
        return "Socket creation failed.";
    case RES_CONNECTION_FAILED:
        return "Failed to establish a connection.";
    case RES_INIT_SSH_SESSION_FAILED:
        return "Failed to initialize SSH session.";
    case RES_SSH_SESSION_START_FAILED:
        return "Failed to start SSH session.";
    case RES_AUTH_PASS_FAILED:
        return "Password authentication failed.";
    case RES_AUTH_KEYBOARD_FAILED:
        return "Keyboard-interactive authentication failed.";
    case RES_AUTH_PUBKEY_FAILED:
        return "Public key authentication failed.";
    case RES_NO_AUTH_METHODS:
        return "No available authentication methods.";
    case RES_INIT_SFTP_FAILED:
        return "Failed to initialize SFTP session.";
    case RES_FAILED_OPEN_FILE_SFTP:
        return "Failed to open file via SFTP.";
    case RES_NOT_INITIALIZED:
        return "SFTP session not initialized.";
    case RES_SFTP_WRITE_FAILED:
        return "Failed to write to file via SFTP.";
    case RES_MOVE_FAILED:
        return "Failed to move or rename file/directory.";
    case RES_DELETE_FAILED:
        return "Failed to delete file/directory.";
    default:
        return "Unknown error.";
    }
}

MINSFTP_RES minsftp::ReadBytes(const std::string sftpFullPath, FILE_DATA& readData, bool nullTerminate) {
    if (!IsInitialized()) {
        fprintf(stderr, "sftp session is not initialized.\n");
        return RES_NOT_INITIALIZED;
    }

    LIBSSH2_SFTP_HANDLE* sftp_handle = nullptr;

    // Open the file
    sftp_handle = libssh2_sftp_open(sftp_session, sftpFullPath.c_str(), LIBSSH2_FXF_READ, 0);

    if (!sftp_handle) {
        fprintf(stderr, "unable to open file %s\n", sftpFullPath.c_str());
        return RES_FAILED_OPEN_FILE_SFTP;
    }

    // read the file
    char buffer[BUFFER_SIZE];
    readData.clear();
    while (true) {
        ssize_t n = libssh2_sftp_read(sftp_handle, buffer, sizeof(buffer));
        if (n > 0) {
            readData.insert(readData.end(), buffer, buffer + n);
        }
        else if (n == 0) { // end of file
            break;
        }
        else {
            fprintf(stderr, "error reading file\n");
            libssh2_sftp_close(sftp_handle);
            return RES_FAILED;
        }
    }

    if (nullTerminate) {
        utils::NullTerminate(readData);
    }

    libssh2_sftp_close(sftp_handle);
    return RES_OK;
}
MINSFTP_RES minsftp::WriteBytes(const std::string sftpFullPath, const FILE_DATA& data) {
    if (!IsInitialized()) {
        fprintf(stderr, "sftp session is not initialized.\n");
        return RES_NOT_INITIALIZED;
    }

    // open file
    LIBSSH2_SFTP_HANDLE* sftp_handle = libssh2_sftp_open(sftp_session, sftpFullPath.c_str(),
        LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT/*create file if not exists*/ | LIBSSH2_FXF_TRUNC /*write instead of append*/,
        LIBSSH2_SFTP_S_IRUSR);

    if (!sftp_handle) {
        fprintf(stderr, "unable to open file %s\n", sftpFullPath.c_str());
        return RES_FAILED_OPEN_FILE_SFTP;
    }

    // write file
    size_t bytesWritten = 0;
    while (data.size() > bytesWritten) {
        size_t bytesToWrite = std::min(data.size(), BUFFER_SIZE); // dont want to write junk data if data is smaller than buffer
        ssize_t rc = libssh2_sftp_write(sftp_handle, reinterpret_cast<const char*>(&(data.at(bytesWritten))), bytesToWrite);
        if (rc < 0) { // wrote less than 0 bytes
            fprintf(stderr, "error writing to sftp file: %s\n", sftpFullPath.c_str());
            libssh2_sftp_close(sftp_handle);
            return RES_SFTP_WRITE_FAILED;
        }
        bytesWritten += rc;
    }
    
    libssh2_sftp_close(sftp_handle);
    return RES_OK;
}

MINSFTP_RES minsftp::SftpMove(const std::string oldSftpFullPath, const std::string newSftpFullPath) {
    if (!IsInitialized()) {
        return RES_NOT_INITIALIZED;
    }

    int rc = libssh2_sftp_rename(sftp_session, oldSftpFullPath.c_str(), newSftpFullPath.c_str());
    return rc == 0 ? RES_OK : RES_MOVE_FAILED;
}
MINSFTP_RES minsftp::SftpDeleteFile(const std::string sftpFullPath) {
    if (!IsInitialized()) {
        return RES_NOT_INITIALIZED;
    }

    int rc = libssh2_sftp_unlink_ex(sftp_session, sftpFullPath.c_str(), (uint32_t)sftpFullPath.length());
    return rc == 0 ? RES_OK : RES_DELETE_FAILED;
}
MINSFTP_RES minsftp::SftpDeleteDir(const std::string sftpFullPath) {
    if (!IsInitialized()) {
        return RES_NOT_INITIALIZED;
    }

    std::vector<std::string> entries = ListDirectory(sftpFullPath);

    for (const auto& entry : entries) {
        std::string fullPath = sftpFullPath + "/" + entry;
        if (IsDirectory(fullPath)) {
            MINSFTP_RES res = SftpDeleteDir(fullPath);
            if (res != RES_OK) {
                return res;
            }
        }
        else {
            MINSFTP_RES res = SftpDeleteFile(fullPath);
            if (res != RES_OK) {
                return res;
            }
        }
    }

    // delete the empty directories
    int rc = libssh2_sftp_rmdir_ex(sftp_session, sftpFullPath.c_str(), (uint32_t)sftpFullPath.length());
    if (rc) {
        fprintf(stderr, "failed to delete dir %s: %d\n", sftpFullPath.c_str(), rc);
        return RES_DELETE_FAILED;
    }

    return RES_OK;
}
MINSFTP_RES minsftp::SftpCopyFile(const std::string oldSftpFullPath, const std::string newSftpFullPath) {
    if (!IsInitialized()) {
        return RES_NOT_INITIALIZED;
    }

    FILE_DATA buffer{};
    auto res = ReadBytes(oldSftpFullPath, buffer);
    if (res != RES_OK) {
        return res;
    }

    return WriteBytes(newSftpFullPath, buffer);
}
MINSFTP_RES minsftp::SftpCopyDir(const std::string oldSftpFullPath, const std::string newSftpFullPath) {
    if (!IsInitialized()) {
        return RES_NOT_INITIALIZED;
    }

    // create destination dir
    int rc = libssh2_sftp_mkdir(sftp_session, newSftpFullPath.c_str(), 0755);
    if (rc != 0 && libssh2_sftp_last_error(sftp_session) != LIBSSH2_FX_FILE_ALREADY_EXISTS) {
        return RES_FAILED;
    }

    // list items in source dir
    std::vector<std::string> entries = ListDirectory(oldSftpFullPath);
    for (const std::string& entry : entries) {
        std::string fullSource = oldSftpFullPath + "/" + entry;
        std::string fullDest = newSftpFullPath + "/" + entry;

        if (IsDirectory(fullSource)) {
            auto res = SftpCopyDir(fullSource, fullDest);
            if (res != RES_OK) {
                return res;
            }
        }
        else {
            auto res = SftpCopyFile(fullSource, fullDest);
            if (res != RES_OK) {
                return res;
            }
        }
    }

    return RES_OK;
}

std::vector<std::string> minsftp::ListDirectory(const std::string sftpFullPath) {
    std::vector<std::string> entries {};

    if (!IsInitialized()) {
        fprintf(stderr, "sftp session is not initialized.\n");
        return entries;
    }

    char buffer[512] {};
    LIBSSH2_SFTP_HANDLE* dir = libssh2_sftp_opendir(sftp_session, sftpFullPath.c_str());
    if (!dir) {
        return entries;
    }

    while (true) {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        int rc = libssh2_sftp_readdir(dir, buffer, sizeof(buffer), &attrs);
        if (rc <= 0) {
            break;
        }

        std::string name(buffer, rc);
        if (name != "." && name != "..") {
            entries.push_back(name);
        }
    }
    libssh2_sftp_closedir(dir);
    return entries;
}

bool minsftp::IsInitialized() const {
    return libssh2_initialized;
}
bool minsftp::IsDirectory(const std::string sftpFullPath) {
    if (!IsInitialized()) {
        return false;
    }

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    LIBSSH2_SFTP_HANDLE* handle = libssh2_sftp_open(sftp_session, sftpFullPath.c_str(), LIBSSH2_FXF_READ, 0);
    if (!handle) {
        return false;
    }

    if (libssh2_sftp_fstat(handle, &attrs) == 0) {
        libssh2_sftp_close(handle);
        return LIBSSH2_SFTP_S_ISDIR(attrs.permissions);
    }
    libssh2_sftp_close(handle);
    return false;
}
