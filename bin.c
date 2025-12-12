#include "Headers.h"


void save_encrypted(uint8_t *IV,
                    uint8_t *TAG,
                    uint8_t *Add, size_t Add_len,
                    uint8_t *ciphertext, size_t ciphertext_len
                     ){

FILE *fp = fopen("Bin", "wb");

if (!fp)
{
    perror("fopen");
    return;
} else{
     // writing the iv, tag, add...

    if(fwrite(IV, 1, 12, fp) != 12){

        perror("Failed to write IV !");
        fclose(fp);
        return;
    }

    if(fwrite(TAG, 1, 16, fp) != 16){

        perror(" Failed to write TAG !");
        fclose(fp);
        return;
    }
    
    if(fwrite(Add, 1, Add_len, fp) != Add_len){

        perror("Failed to write Add !");
        fclose(fp);
        return;
    }

    if(fwrite(ciphertext, 1, ciphertext_len, fp) != ciphertext_len){

        perror("Failed to write cipher !");
        fclose(fp);
        return;
    }

    fclose(fp);
}
}

void Fd_key(uint8_t *Key, uint8_t *salt){
    FILE *fkey = fopen("Kbin", "wb");

    if(!fkey)
    {
        perror("fopen");
        return;
    } else{

       if(fwrite(Key, 1, 32, fkey) != 32){

        perror("Key deviration Failed !");
        fclose(fkey);
        return;
       }

       if(fwrite(salt, 1, 16, fkey) != 16){

        perror("Salt Failed !");
        fclose(fkey);
        return;
       }
   
    }
    
    fclose(fkey);
}

uint8_t read_fp(const char *fp, uint8_t *IV,
                uint8_t Tag,
                uint8_t *Add, size_t Add_len,
                uint8_t *ciphertext, size_t ciphertext_len){

                }
