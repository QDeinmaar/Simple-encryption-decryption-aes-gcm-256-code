#include "Headers.h"

#define IV_SIZE 16
#define KEY_SIZE 32

uint8_t IV[16] = {0};
uint8_t Key[32] = {0};
uint8_t AAD[] = "7G2U8T8S";
uint8_t salt[16] = {0};
uint32_t m_cost = 16 * 1024;
uint32_t t_cost = 2;
uint32_t parallelism = 2;
uint8_t Tag[16];
size_t AAD_len;

 void display_encryption_header();

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
    int action;

        printf("CHoose an option \n 1.Encrypt\n 2.Decrypt\n 3.Exit\n");
        scanf("%d", &choice);
         while(getchar() != '\n');
       

        switch(choice){
            case 1:
            printf("You choosed Encryption do you want to encrypt a \n 1.Text\n 2.File\n");
            scanf("%d", &action);
             while(getchar() != '\n');

        if(action == 1){
            printf("Please enter ur unique password to encrypt : ");
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

            size_t AAD_len = strlen((char*)AAD); 


            Encrypt_text(plaintext, plaintext_len, Ciphertext, &Ciphertext_len, AAD, AAD_len, Key, IV, Tag );

            printf("The encrypted text is : (%d Bytes)", Ciphertext_len);
            for(int i = 0; i < Ciphertext_len; i++){
                printf("%02x", Ciphertext[i]);
            }

            printf("\n");

            memset(password, 0, sizeof(password));
            memset(plaintext, 0, sizeof(plaintext));
            memset(Key, 0, sizeof(Key));
            return 0;
            
        }
            if( action == 2);
            
    }
    
    
    return 0;
}





