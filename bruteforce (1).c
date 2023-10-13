#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <stdlib.h>
#include <mpi.h>

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

int main(int argc, char* argv[]) {
    int process_id, num_processes;

    // Initialize the MPI environment
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &process_id);
    MPI_Comm_size(MPI_COMM_WORLD, &num_processes);

    char* key_text = "10";  // Plaintext key for encryption
    DES_cblock key;
    memset(&key, 0, sizeof(key));
    strncpy((char*)key, key_text, sizeof(key));

    if (process_id == 0) {
        // This is the main process
        printf("Encrypting with key: %s\n", key_text);

        FILE* plain = fopen("plaintext.txt", "rb");
        fseek(plain, 0, SEEK_END);
        long length = ftell(plain);
        fseek(plain, 0, SEEK_SET);

        unsigned char* plaintext = malloc(length);
        fread(plaintext, 1, length, plain);
        fclose(plain);

        FILE* encrypted = fopen("encrypted_mpi.txt", "wb");
        encrypt_des(plaintext, length, encrypted, &key);
        fclose(encrypted);
        free(plaintext);

        // Wait for messages from worker processes
        int successful_key;
        MPI_Status status;
        MPI_Recv(&successful_key, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &status);
        printf("Main process received successful decryption with key: %d from process %d\n", successful_key, status.MPI_SOURCE);

    } else {
        // Worker processes

        unsigned char* decrypted_buffer = NULL;
        for (int k = process_id; k < 256; k += num_processes) {
            DES_cblock trial_key;
            memset(&trial_key, 0, sizeof(trial_key));
            trial_key[0] = (unsigned char)k;

            FILE* encrypted = fopen("encrypted_mpi.txt", "rb");
            if (!encrypted) {
                printf("Error: Process %d could not open encrypted file.\n", process_id);
                continue;
            }
            fseek(encrypted, 0, SEEK_END);
            long encrypted_length = ftell(encrypted);
            fseek(encrypted, 0, SEEK_SET);

            if (!decrypted_buffer) {
                decrypted_buffer = malloc(encrypted_length + 1);  // +1 for null terminator
                if (!decrypted_buffer) {
                    printf("Error: Process %d could not allocate memory for decryption.\n", process_id);
                    fclose(encrypted);
                    continue;
                }
            }

            decrypt_des(encrypted, decrypted_buffer, &trial_key);
            if (ferror(encrypted)) {
                printf("Error: Process %d encountered an error reading the encrypted file.\n", process_id);
                fclose(encrypted);
                continue;
            }
            decrypted_buffer[encrypted_length] = '\0';  // Ensure null termination
            fclose(encrypted);

            if (strncmp((char*)decrypted_buffer, "Hello", 5) == 0) {
                printf("Process %d successfully decrypted the message with key: %d\n", process_id, k);

                MPI_Send(&k, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);
                break;
            }
        }

        if (decrypted_buffer) {
            free(decrypted_buffer);
        }
    }

    MPI_Finalize();
    return 0;
}