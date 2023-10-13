#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>
#include <stdlib.h>

#define BLOCK_SIZE 8

void pad(unsigned char* src, unsigned char* dest, int length) {
    int padding = BLOCK_SIZE - (length % BLOCK_SIZE);
    memcpy(dest, src, length);
    for (int i = 0; i < padding; i++) {
        dest[length + i] = padding;
    }
}

void unpad(unsigned char* src, unsigned char* dest, int length) {
    int padding = src[length - 1];
    memcpy(dest, src, length - padding);
}

void encrypt_des(unsigned char* plaintext, int len, FILE* out, DES_cblock* key) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);

    int padded_len = len + (BLOCK_SIZE - (len % BLOCK_SIZE));
    unsigned char* padded_text = malloc(padded_len);
    pad(plaintext, padded_text, len);

    unsigned char outbuf[BLOCK_SIZE];
    DES_cblock ivec;
    memset(&ivec, 0, sizeof(ivec));

    for (int i = 0; i < padded_len; i += BLOCK_SIZE) {
        DES_ncbc_encrypt(padded_text + i, outbuf, BLOCK_SIZE, &schedule, &ivec, DES_ENCRYPT);
        fwrite(outbuf, sizeof(unsigned char), BLOCK_SIZE, out);
    }

    free(padded_text);
}

void decrypt_des(FILE* in, FILE* out, DES_cblock* key) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);

    unsigned char buffer[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE];
    DES_cblock ivec;
    memset(&ivec, 0, sizeof(ivec));

    int total = 0;
    while (fread(buffer, sizeof(unsigned char), BLOCK_SIZE, in)) {
        DES_ncbc_encrypt(buffer, outbuf, BLOCK_SIZE, &schedule, &ivec, DES_DECRYPT);
        total += BLOCK_SIZE;
        if (total == BLOCK_SIZE) {  // only for the last block
            int padding = outbuf[BLOCK_SIZE - 1];
            fwrite(outbuf, sizeof(unsigned char), BLOCK_SIZE - padding, out);
            fwrite(outbuf, sizeof(unsigned char), BLOCK_SIZE - padding, stdout);

        } else {
            fwrite(outbuf, sizeof(unsigned char), BLOCK_SIZE, out);
            fwrite(outbuf, sizeof(unsigned char), BLOCK_SIZE, stdout);

        }
    }

}

int main() {
    char* key_text = "10";  // Plaintext key
    DES_cblock key;
    memset(&key, 0, sizeof(key));
    strncpy((char*)key, key_text, sizeof(key));

    FILE* plain = fopen("plaintext.txt", "rb");
    fseek(plain, 0, SEEK_END);
    long length = ftell(plain);
    fseek(plain, 0, SEEK_SET);

    unsigned char* plaintext = malloc(length);
    fread(plaintext, 1, length, plain);
    fclose(plain);

    FILE* encrypted = fopen("encrypted.txt", "wb");
    encrypt_des(plaintext, length, encrypted, &key);
    fclose(encrypted);

    encrypted = fopen("encrypted.txt", "rb");
    FILE* decrypted = fopen("decrypted.txt", "wb");

    clock_t start_time, end_time;
    start_time = clock();

    decrypt_des(encrypted, decrypted, &key);

    end_time = clock();
    double time_taken = ((double)end_time - start_time) / CLOCKS_PER_SEC; // in seconds

    printf("Decryption took %f seconds to execute.\n", time_taken);

    fclose(encrypted);
    fclose(decrypted);

    free(plaintext);

    return 0;
}
