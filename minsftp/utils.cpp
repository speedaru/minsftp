#include "utils.h"

UTILS_RES utils::ReadFile(const char* filePath, PFILE_DATA data) {
	std::ifstream fs(filePath, std::ios::binary);

	if (!fs.is_open()) {
		fprintf(stderr, "failed to open ifstream to: '%s'\n", filePath);
		return UTILS_FAILED;
	}

	// Clear previous content if any
	data->clear();

	(*data).assign(std::istreambuf_iterator<char>(fs), std::istreambuf_iterator<char>());

	// Check for any stream errors
	if (fs.bad()) {
		fprintf(stderr, "Error occurred while reading file: '%s'\n", filePath);
		return UTILS_FAILED;
	}

	return UTILS_OK;
}

void utils::NullTerminate(FILE_DATA& fileData) {
	if (fileData.at(fileData.size() - 1) != '\0') {
		fileData.push_back('\0');
	}
}