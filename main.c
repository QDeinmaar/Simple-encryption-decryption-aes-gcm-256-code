#include "Headers.h"

#define IV_SIZE 12
#define KEY_SIZE 32
#define TAG_LEN 16
#define AAD_len 8

uint8_t IV[12] = {0};
uint8_t Key[32] = {0};
uint8_t AAD[AAD_len] = {'7','G','2','U','8','T','8','S'};
uint8_t salt[16] = {0};
uint32_t m_cost = 16 * 1024;
uint32_t t_cost = 2;
uint32_t parallelism = 2;
uint8_t Tag[16];

 void display_encryption_header();

 void dump_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    

    uint8_t Ciphertext[1024];
    size_t Ciphertext_len;
    uint8_t plaintext[1024];
    size_t plaintext_len;

    unsigned char password[128];

    display_encryption_header();
    
    if (1 != RAND_bytes(salt, sizeof(salt)) || 1 != RAND_bytes(IV, sizeof(IV))) {
        printf("Error generating random bytes\n");
        return -1;
    }

    int choice;
    

        printf("CHoose an option \n 1.Encrypt\n 2.Decrypt\n 3.Exit\n");
        scanf("%d", &choice);
         while(getchar() != '\n');
       

        switch(choice){
            case 1: {


            printf("Please enter your unique password to encrypt : ");
            scanf("%127s", password);
             while(getchar() != '\n');

            hash_password(password, strlen(password), salt, sizeof(salt), Key, sizeof(Key), m_cost, t_cost, parallelism);

            printf("Enter the text you want to Encrypt :");
            fgets(plaintext, sizeof(plaintext), stdin);
            size_t plaintext_len = strlen((char*)plaintext);
            

        if( plaintext_len > 0 && plaintext[plaintext_len - 1] == '\n'){
                plaintext[plaintext_len -1] = '\0';
                plaintext_len--;
            }

            Encrypt_text(plaintext, plaintext_len, Ciphertext, &Ciphertext_len, AAD, AAD_len, Key, IV, Tag );

            size_t Encrypt_text_len = sizeof(salt) + IV_SIZE + Ciphertext_len + TAG_LEN;
            uint8_t Encrypt_text_block[Encrypt_text_len];

            memcpy(Encrypt_text_block, salt, sizeof(salt));
            memcpy(Encrypt_text_block + sizeof(salt), IV, IV_SIZE);
            memcpy(Encrypt_text_block + sizeof(salt) + IV_SIZE,
                Ciphertext, Ciphertext_len);
            memcpy(Encrypt_text_block + sizeof(salt) + IV_SIZE + Ciphertext_len,
                Tag, TAG_LEN);


            printf("The encrypted text is : (%d Bytes)\t", Encrypt_text_len);
        for(int i = 0; i < Encrypt_text_len; i++){
                printf("%02x", Encrypt_text_block[i]);
            }

            memset(password, 0, sizeof(password));
            memset(plaintext, 0, sizeof(plaintext));
            memset(Key, 0, sizeof(Key));
        return 0;
            }

        case 2:
        
            char hex_input[2048]; 
            uint8_t Encrypt_text_bytes[1024]; 
        
            printf("Enter the Hex text: ");
        if (scanf("%2047s", hex_input) != 1) return 1;

            size_t hex_len = strlen(hex_input);
            size_t full_len = hex_len / 2;

    
        for (size_t i = 0; i < full_len; i++) {
            unsigned int temp;
        
            sscanf(&hex_input[i * 2], "%02x", &temp);
            Encrypt_text_bytes[i] = (uint8_t)temp;
        }


            printf("\n--- Debugging Data ---\n");
            printf("Full length: %zu bytes\n", full_len);
    
            memcpy(salt, Encrypt_text_bytes, sizeof(salt));
            memcpy(IV, Encrypt_text_bytes + sizeof(salt), IV_SIZE);

            size_t c_len = full_len - sizeof(salt) - IV_SIZE - TAG_LEN;
            memcpy(Ciphertext,
                Encrypt_text_bytes + sizeof(salt) + IV_SIZE,
                c_len);

            memcpy(Tag, Encrypt_text_bytes + full_len - TAG_LEN, TAG_LEN);

            
            printf("Enter password to decrypt: ");
            scanf("%127s", password);
        while (getchar() != '\n');

            hash_password(password, strlen(password),
                        salt, sizeof(salt),
                        Key, sizeof(Key),
                        m_cost, t_cost, parallelism);

            printf("\n --- Information ---\n");
            printf("IV: "); dump_hex(IV, IV_SIZE);
            printf("AAD: "); dump_hex(AAD, AAD_len);
            printf("KEY: "); dump_hex(Key, 32);
            printf("TAG: "); dump_hex(Tag, 16);
            printf("\n"); 

            int result_len = Decrypted_text(Ciphertext, &c_len, AAD, AAD_len, Tag, Key, IV, plaintext);

        if(result_len >= 0) {
            plaintext[result_len] = '\0';
            printf("Decrypted Message: %s\n", (char*)plaintext);
        }
        else {
            printf("Decryption failed! The Tag or Key is likely wrong.\n");
        }
        // Clear sensitive data
            memset(password, 0, sizeof(password));
            memset(plaintext, 0, sizeof(plaintext));
            memset(Key, 0, sizeof(Key));
        
        return 0;

    case 3:
        printf("Exiting\n");
        break;

    default:
        printf("Invalid choice!\n");
        return 1;
    }
    return 0;
}

        
