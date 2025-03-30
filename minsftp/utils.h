#pragma once
#include <filesystem>
namespace fs = std::filesystem;
#include <vector>
#include <fstream>

#ifndef FILE_DATA
	#define FILE_DATA std::vector<uint8_t>
#endif // !FILE_DATA
#define PFILE_DATA FILE_DATA*

enum UTILS_RES {
	UTILS_OK,
	UTILS_FAILED,
};

namespace utils {
	UTILS_RES ReadFile(const char* filePath, PFILE_DATA data);
	void NullTerminate(FILE_DATA& fileData);
}