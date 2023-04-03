#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <stdexcept>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#include <Shlwapi.h>

class AES256 {
public:
    static char* encrypt(const char* plaintext, const std::string& key, const std::string& iv, int len) {
        // Initialize the encryption context
        HCRYPTPROV hProv = NULL;
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("Failed to acquire context for encryption.");
        }

        HCRYPTKEY hKey = NULL;
        if (!CryptGenKey(hProv, CALG_AES_256, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to create encryption key.");
        }

        auto mode = CRYPT_MODE_CBC;

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set encryption mode.");
        }

        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.c_str(), 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set encryption IV.");
        }

        // Encrypt the data
        DWORD encrypted_len = 0;
        DWORD block_size = 0;
        DWORD data_len = len;

        if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &block_size, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to get encryption block size.");
        }

        BYTE* encrypted_data = new BYTE[data_len + block_size];
        std::cout << "encrypted_data size: " << data_len + block_size << std::endl;
        memcpy(encrypted_data, plaintext, data_len);

        if (!CryptEncrypt(hKey, NULL, TRUE, 0, encrypted_data, &data_len, data_len + block_size)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            delete[] encrypted_data;
            throw std::runtime_error("Failed to encrypt data.");
        }

        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        // Return the encrypted data
        return (char*)encrypted_data;
    }

    static char* decrypt(std::vector<char> ciphertext, const std::string& key, const std::string& iv) {
        // Initialize the decryption context
        HCRYPTPROV hProv = NULL;
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("Failed to acquire context for decryption.");
        }

        HCRYPTKEY hKey = NULL;
        if (!CryptGenKey(hProv, CALG_AES_256, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to create decryption key.");
        }

        auto mode = CRYPT_MODE_CBC;

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set encryption mode.");
        }

        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.c_str(), 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set decryption IV.");
        }

        // Decrypt the data
        DWORD decrypted_len;
        DWORD block_size = 0;
        DWORD data_len = (DWORD)ciphertext.size();
        auto dat = ciphertext.data(); 
        BYTE* pBuf = new BYTE[data_len];
        for (size_t i = 0; i < data_len; i++) {
            pBuf[i] = dat[i];
        }
        //StrCpyA((char*)pBuf, dat);
         
        if (!CryptDecrypt(hKey, NULL, TRUE, 0, pBuf, &data_len)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to decrypt data.");
        }

        decrypted_len = data_len;

        BYTE* decrypted_data = new BYTE[data_len + block_size];
        memcpy(decrypted_data, pBuf, data_len);

        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        // Return the decrypted data
        return (char*)decrypted_data;
    }
};