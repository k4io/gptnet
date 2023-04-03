#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <stdexcept>

class AES256 {
public:
    static std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv) {
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

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)CRYPT_MODE_CBC, 0)) {
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
        DWORD data_len = (DWORD)plaintext.length();

        if (!CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &block_size, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to get encryption block size.");
        }

        BYTE* encrypted_data = new BYTE[data_len + block_size];
        memcpy(encrypted_data, plaintext.c_str(), data_len);

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
        std::string result((char*)encrypted_data, data_len);
        delete[] encrypted_data;
        return result;
    }


    static std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
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

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)CRYPT_MODE_CBC, 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set decryption mode.");
        }
        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.c_str(), 0)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to set decryption IV.");
        }

        // Decrypt the data
        DWORD decrypted_len = 0;
        DWORD block_size = 0;
        DWORD data_len = (DWORD)ciphertext.length();

        if (!CryptDecrypt(hKey, NULL, TRUE, 0, NULL, &block_size)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("Failed to get decryption block size.");
        }

        BYTE* decrypted_data = new BYTE[data_len + block_size];
        memcpy(decrypted_data, ciphertext.c_str(), data_len);

        if (!CryptDecrypt(hKey, NULL, TRUE, 0, decrypted_data, &data_len)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            delete[] decrypted_data;
            throw std::runtime_error("Failed to decrypt data.");
        }

        // Clean up
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        // Return the decrypted data
        std::string result((char*)decrypted_data, data_len);
        delete[] decrypted_data;
        return result;
    }
};