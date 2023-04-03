#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include "../plusaes.hpp"
#include <vector>
#include <vector>
#include <algorithm>
#include <random>

std::vector<char>::const_iterator find_pattern(const std::vector<char>& data)
{
    const char* target = "fuck";
    auto target_size = std::strlen(target);

    auto iter = std::search(data.begin(), data.end(), target, target + target_size);

    if (iter != data.end()) {
        return iter;
    }
    else {
        return data.end();
    }
}

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


const int KEY_SIZE = 32;
const int IV_SIZE = 16;
const int BUFFER_SIZE = 4096;
const int APPEND_OFFSET = 0xA4C0;
const char* OUTPUT_FILE = "stub.exe";

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    // Open the file in binary mode
    std::ifstream file(argv[1], std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file");
    }

    // Determine the size of the file
    file.seekg(0, std::ios::end);
    std::size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file into a vector
    std::vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);

    // Check for read errors
    if (!file) {
        throw std::runtime_error("Error reading file");
    }

    std::cout << "Read " << fileSize << " bytes from input file" << std::endl;

    // Use the specified key and IV

    // Encrypt the input buffer using AES256-CBC with the specified key and IV
    auto og_data = fileData.data();
    //encrypted_buffer = AES256::encrypt(og_data, key, iv, encrypted_size);

    const std::vector<unsigned char> key = plusaes::key_from_string(&"K9VR3bmIOWVa8MCSzPb5wafNCvF4O1yD"); // 32-char = 128-bit

    const unsigned char iv[16] = { 'i', 'v', 'f', 'o', 'r', 'a', 'e', 's', 'e', 'n', 'c', 'r', 'y', 'p', 't', 'r'};

    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(fileSize);
    std::vector<unsigned char> encrypted(encrypted_size);

    plusaes::encrypt_cbc((unsigned char*)og_data, fileSize, &key[0], 32, &iv, &encrypted[0], encrypted_size, true);


    std::ofstream fenc;
    fenc.open("enc.out");
    fenc.write((char*)encrypted.data(), encrypted.size());
    fenc.close();
    //encrypted_buffer = fileData.data();
    //encrypted_buffer = new char[encrypted_size] { 'c', 'o', 'c', 'k', 's', 'u', 'c', 'k', 'e', 'r' };

    std::cout << "Encrypted " << fileSize << " bytes using key and IV (" << encrypted_size << ")" << std::endl;

    // Append the encrypted data to the o.exe file
    std::fstream output_file(OUTPUT_FILE, std::ios::in | std::ios::out | std::ios::binary);
    if (!output_file) {
        std::cerr << "Error: could not open output file" << std::endl;
        return 1;
    }

    output_file.seekg(0, std::ios::end);
    std::size_t outputFileSize = output_file.tellg();
    output_file.seekg(0, std::ios::beg);

    //output_file.seekp(APPEND_OFFSET, std::ios::beg);
    std::vector<char> outputData(outputFileSize);
    output_file.read(outputData.data(), outputFileSize);
    auto iter = find_pattern(outputData);

    if (iter != outputData.end()) {
        auto offset = std::distance<std::vector<char>::const_iterator>(outputData.begin(), iter);
        std::cout << "Found 'fuck' at offset 0x" << std::hex << std::uppercase << offset << std::endl;
        output_file.seekp(offset, std::ios::beg);
        output_file.write((const char*)encrypted.data(), encrypted.size());
        std::cout << "Appended " << std::dec << encrypted_size << " bytes to output file!\nFinished!" << std::endl;
    }
    else {
        output_file.seekp(APPEND_OFFSET, std::ios::beg);
        output_file.write((const char*)encrypted.data(), encrypted.size());
        std::cout << "Appended " << std::dec << encrypted_size << " bytes to output file!\nFinished!" << std::endl;
    }
        //std::cout << "Couldn't find 'fuck' inside " << OUTPUT_FILE << std::endl;

    output_file.close();


    //delete[] encrypted_buffer;

    return 0;
}