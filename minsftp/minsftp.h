/* Copyright (C) The libssh2 project and its contributors.
 *
 * Sample showing how to do SFTP transfers.
 *
 * The sample code has default values for host name, user name, password
 * and path to copy, but you can specify them on the command line like:
 *
 * $ ./sftp 192.168.0.1 user password /tmp/secrets -p|-i|-k
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#define NOMINMAX

#include "libssh2_setup.h"
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "crypt32.lib")

#include <iostream>
#include <filesystem>
#include <sstream>
#include <algorithm>
namespace fs = std::filesystem;

#include "utils.h"

#ifdef WIN32
#define write(f, b, c)  write((f), (b), (unsigned int)(c))
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <string.h>

// include lib files
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssh2.lib")
#pragma comment(lib, "libssl.lib")

constexpr size_t BUFFER_SIZE = 4096;

enum AUTH_TYPE {
	AUTH_PASSWORD,
	AUTH_PUBKEY,
	AUTH_KEYBOARD,
};

enum MINSFTP_RES {
	RES_OK,
	RES_FAILED,
	RES_WSA_FAILED,
	RES_INIT_LIBSSH2_FAILED,
	RES_SOCKET_FAILED,
	RES_CONNECTION_FAILED,
	RES_INIT_SSH_SESSION_FAILED,
	RES_SSH_SESSION_START_FAILED,
	RES_AUTH_PASS_FAILED,
	RES_AUTH_KEYBOARD_FAILED,
	RES_AUTH_PUBKEY_FAILED,
	RES_NO_AUTH_METHODS,
	RES_INIT_SFTP_FAILED,
	RES_FAILED_OPEN_FILE_SFTP,
	RES_NOT_INITIALIZED,
	RES_SFTP_WRITE_FAILED,
	RES_MOVE_FAILED,
	RES_DELETE_FAILED
};


// a_ stands for auth
struct a_pubkey {
	FILE_DATA privKeyData;
	LPCSTR passphrase;
};

struct a_password {
	LPCSTR password;
};

class Client {
public:
	std::string user{};
	uint32_t hostaddr{};
	u_short port{};

	// format: user@hostaddr:port
	Client(const char* format);
	Client() {}

	LPCSTR User() const {
		return user.c_str();
	}

private:
	bool IsValidFormat(const char* format);
};

class minsftp {
private:
	AUTH_TYPE authType;

	Client client;
	a_pubkey pubkey{};
	a_password password{};

	bool libssh2_initialized{ false };
	libssh2_socket_t sock{};
	LIBSSH2_SESSION* session = NULL;
	LIBSSH2_SFTP* sftp_session{ nullptr };
	LIBSSH2_SFTP_HANDLE* sftp_handle{ nullptr };

public:
	minsftp(Client _client, AUTH_TYPE _authType, void* authVal);
	~minsftp();

	MINSFTP_RES Init();
	void Shutdown();

	static FILE_DATA ReadPrivateKeyFromFile(const std::string path);

	const char* ResToStr(const MINSFTP_RES res);

	// read bytes from a file into vector
	// nullTerminate: add \0 to the end of data
	MINSFTP_RES ReadBytes(const  std::string sftpFullPath, FILE_DATA& readData, bool nullTerminate = false);
	// write bytes to a file from vector
	MINSFTP_RES WriteBytes(std::string sftpFullPath, const FILE_DATA& data);

	// move/rename file or dir
	MINSFTP_RES SftpMove(const std::string oldSftpFullPath, const std::string newSftpFullPath);
	// delete file
	MINSFTP_RES SftpDeleteFile(const std::string sftpFullPath);
	// delete dir recursivly
	MINSFTP_RES SftpDeleteDir(const std::string sftpFullPath);
	// copy file
	MINSFTP_RES SftpCopyFile(const std::string oldSftpFullPath, const std::string newSftpFullPath);
	// copy dir
	MINSFTP_RES SftpCopyDir(const std::string oldSftpFullPath, const std::string newSftpFullPath);

	std::vector<std::string> ListDirectory(const std::string sftpFullPath);

	bool IsInitialized() const;
	bool IsDirectory(const std::string sftpFullPath);
};
