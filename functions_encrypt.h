
#pragma once

#ifndef FUNCTIONS_ENCRYPT_H
#define FUNCTIONS_ENCRYPT_H

#include <stdint.h>
#include <stddef.h>

int generate_rand_bytes(char *buffer, int length);

int hash_password(char *password, int password_len,  
            unsigned char *salt, int salt_len,
            unsigned char *hash, int hash_len,
            uint32_t t_cost, uint32_t m_cost, uint32_t parallelism);


int Encrypt_text(uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *Cipher, size_t *Cipher_len,
                 uint8_t *AAD, size_t AAD_len,
                 uint8_t *Key, uint8_t *IV,
                    uint8_t *Tag);

int Decrypted_text(uint8_t *ciphertext, size_t *ciphertext_len,
                   uint8_t *AAD, size_t AAD_len,
                   uint8_t *Tag, uint8_t Key, uint8_t *IV, uint8_t *plaintext);




#endif