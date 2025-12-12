#include "Headers.h"


void save_encrypted(uint8_t *IV, size_t IV_len,
                    uint8_t TAG, size_t Tag_len,
                    uint8_t Add, size_t Add_len,
                    uint8_t salt, size_t salt_len,
                    uint8_t ciphertext, size_t ciphertext_len
                     ){

FILE *fp = fopen("Bin", "wb");

if (!fp)
{
    perror("fopen");
    return;
} else{
     // writing the iv, tag, add...

    fwrite(IV, 1, IV_len, fp);

    fwrite(TAG, 1, Tag_len, fp);
    
    fwrite(Add, 1, Add_len, fp);

    fwrite(salt, 1, salt_len, fp);

    fwrite(ciphertext, 1, ciphertext_len, fp);

    fclose(fp);
}


}

