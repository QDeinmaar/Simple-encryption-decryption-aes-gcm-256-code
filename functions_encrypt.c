
#include "Headers.h"



void display_encryption_header() {
    printf("\n");
    printf("    ================================\n");
    printf("            CRYPTO TOOLKIT          \n");
    printf("         AES-GCM ENCRYPTION         \n");
    printf("    ================================\n\n");
}



int generate_rand_bytes(char *buffer, int length){  
    if( 1 != RAND_bytes((unsigned char*)buffer, length)){
        printf("Erreur generating bytes\n");
        return 0;
    }
    return 1;
}

int hash_password(char *password, int password_len,  
            unsigned char *salt, int salt_len,
            unsigned char *hash, int hash_len,
            uint32_t m_cost, uint32_t t_cost, uint32_t parallelism){
        
        if(password == 0 || salt == 0 || hash == 0){
            printf("Error : NUll pointer is provided\n");
            return 0;
        }

        if(password_len <= 0 || salt_len <= 0 || hash_len <= 0 ){
            printf("Error Invalid length pass=%d, salt=%d, hash%d \n", password_len, salt_len, hash_len);
            return 0;
        }

        if(t_cost < 1 || m_cost < 8 * 1024 || parallelism < 1 ){
            printf("Error Invalid Argon parametrs t_cost = %d, m_cost = %d, parallelism = %d\n", t_cost, m_cost, parallelism);
            return 0;
        }
                
                int result = argon2id_hash_raw(t_cost, m_cost, parallelism, 
                                password, password_len, salt, salt_len,
                                hash, hash_len);
        if(result != ARGON2_OK){
            printf("Hashing the password Failed\n", argon2_error_message(result));
            return 0;
        }

        switch (ARGON2_OK)
        {
        case ARGON2_MEMORY_ALLOCATION_ERROR:
            printf("Please reduce the m_cost parameter\n");
            break;
        case ARGON2_OUTPUT_PTR_NULL:
        printf("Hash buffer is NULL\n");
        break;
        default:
            break;
        }
        return 1;
                    }

int Encrypt_text(uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *Ciphertext, size_t *Ciphertext_len,
                 uint8_t *AAD, size_t AAD_len,
                 uint8_t *Key, uint8_t *IV,
                    uint8_t *Tag)
                   {
                        int len = 0;
                        int total_cipher_len = 0;

                    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

                    if(!ctx){
                        printf("EVP_CIPHER_new had failed\n");
                        return 0;
                    }

                    if( !EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
                        printf("EVP_CIPHER initialisation failed\n");
                        ERR_print_errors_fp(stderr);
                        EVP_CIPHER_CTX_free(ctx);
                        return 0;
                    }

                   if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)){
                        printf("Setting teh IV length has Failed\n");
                        return 0;
                   }


                    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, Key, IV)){
                        printf("EVP_CIPHER initialisation failed\n");
                        ERR_print_errors_fp(stderr);
                        EVP_CIPHER_CTX_free(ctx);
                        return 0;
                    }
                    
                    if( AAD && AAD_len > 0){
                        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, AAD, (int) AAD_len)){
                            printf("Adding the ADD has failed\n");
                            ERR_print_errors_fp(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                            return 0;
                        }
                    }
                    
                    if(1 != EVP_EncryptUpdate(ctx, Ciphertext, &len, plaintext, (int) plaintext_len)){
                        printf("Encryption Failed\n");
                        ERR_print_errors_fp(stderr);
                        EVP_CIPHER_CTX_free(ctx);
                        return 0;
                    }
                    total_cipher_len = len;

                    if(1 != EVP_EncryptFinal_ex(ctx, Ciphertext + len, &len)){
                        printf("Final Encryption Failed\n");
                        ERR_print_errors_fp(stderr);
                        EVP_CIPHER_CTX_free(ctx);
                        return 0;
                    }
                    total_cipher_len += len;
                    *Ciphertext_len = (size_t) total_cipher_len;

                    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, Tag))
                    {
                       printf("Getting the tag had Failed\n");
                       EVP_CIPHER_CTX_free(ctx);
                       return 0;
                    }
                    
                    EVP_CIPHER_CTX_free(ctx);
                    return 1;

                    }


int Decrypted_text (uint8_t *ciphertext, uint8_t *ciphertext_len,
                    uint8_t *ADD, uint8_t ADD_len,
                    uint8_t *Tag, uint8_t Key, uint8_t *IV, uint8_t plaintext)
                    {
                        EVP_CIPHER_CTX *ctx;
                        int len;
                        int plaintext_len;
                        int ret;

                        if(!(ctx = EVP_CIPHER_CTX_new())) {

                        
                            printf("Creation has failed !");
                            ERR_print_errors(stderr);
                        }

                        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm, NULL, NULL, NULL)){
                            printf("Initialisation has Failed !");
                            ERR_print_errors(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                        }

                        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)){
                            printf("Setting the IV failed !");
                            ERR_print_errors(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                        }

                        if(!EVP_DecryptInit_ex(ctx, NULL, NULL, Key, IV)){
                            printf("EVP failed to initialize !");
                            ERR_print_errors(stderr);
                            EVP_CHIPHER_CTX_free(ctx);
                        }

                        if(!EVP_DecryptUpdate(ctx, NULL, &len, ADD, (int) ADD_len)){
                            printf("Providing the ADD failed !");
                            ERR_print_errors(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                        }

                        if(! EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int) ciphertext_len)){
                            printf("Decryption failed !");
                            ERR_print_errors(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                        }

                        plaintext_len = len;

                        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Tag)){
                            printf("Failed Tag !");
                            ERR_print_errors(stderr);
                            EVP_CIPHER_CTX_free(ctx);
                        }

                        ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

                        EVP_CIPHER_CTX_free(ctx);
    
                    }



/* 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
    

int generate_random_bytes(unsigned char *buffer, int length){
    if(1 != RAND_bytes(buffer, length)){
        printf("Error generating random bytes\n");
        return 0;
    }
        return 1;
}

int hash_password( char *password, size_t password_len,
     unsigned char *salt, size_t salt_len,
     uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
     unsigned char* hash, size_t hash_len)
     {
       int result = argon2id_hash_raw(
                t_cost, m_cost, parallelism,
            password, password_len,
            salt, salt_len,
            hash, hash_len
        );

        if(result != ARGON2_OK){
            printf("Error hashing password: %s\n", argon2_error_message(result));
            return 0;
        }

        return 1;
     }

int Encrypt_text( uint8_t *plaintext, size_t *plaintext_len,
            uint8_t *Ciphertext, size_t *Ciphertext_lent,
            uint8_t *Key,
            uint8_t *IV,
            uint8_t *AAD, size_t *AAD_len,
            uint8_t *tag){

    int len = 0;
    int ciphertext_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        printf("EVP_CIPHER_CTX_new failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        printf("EVP_EncryptInit_ex0 failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, Key, IV)){
        printf("EVP_EncryptInit_ex1 Failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(AAD && AAD_len > 0){
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, AAD, (int)*AAD_len)){
        printf("EVP_EncryptUpdate AAD failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    }


    if(1 != EVP_EncryptUpdate(ctx, Ciphertext, &len, plaintext, (int)*plaintext_len)){
        printf("EVP_EncryptUpdate plaintext failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
          }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, Ciphertext + len, &len)){
        printf("EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    *Ciphertext_lent = ciphertext_len;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        printf("EVP_CIPHER_CTX_ctrl failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
*/ 

/*
int encrypt_text(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len; 

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        printf("EVP_EncryptInit_ex failed\n");
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext))) {
        printf("EVP_EncryptUpdate failed\n");
        return -1;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("EVP_EncryptFinal_ex failed\n");
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
} */


