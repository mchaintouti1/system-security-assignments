#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <malloc.h>


void keyStorageFile(char *type, unsigned int key_length, mpz_t n, mpz_t key){

    char filename[50];
    snprintf(filename, sizeof(filename), "%s%u.key", type, key_length);
    FILE *kStorefile = fopen(filename, "w");

    if(!kStorefile){
        perror("Sorry!Unable to open key storage file.");
        return;
    }

    gmp_fprintf(kStorefile, "%Zd %Zd", n, key);
    fclose(kStorefile);
}

void generateRSAKeyPair(mpz_t n, mpz_t e, mpz_t d, unsigned int key_length){

    gmp_randstate_t state;
    mpz_t p, q, lambda, p1, q1, gcd1, remainder;

    //Initializing GMP variables
    mpz_inits(p, q, lambda, p1, q1, gcd1, remainder, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    //Generate a random p that would be key_length/2
    mpz_urandomb(p, state, key_length/2);
    //If mpz_probab_prime_p=2 then p is prime (15-50 is reasonable reps)
    while(mpz_probab_prime_p(p,30) < 1)
        mpz_nextprime(p,p); //if mpz_probab_prime_p != 2 then p is not prime, take the next prime

    //Generate a random q that would be key_length/2
    mpz_urandomb(q, state, key_length/2);
    //If mpz_probab_prime_p=2 then p is prime (15-50 is reasonable reps)
    while(mpz_probab_prime_p(q,30) < 1)
        mpz_nextprime(q,q); //if mpz_probab_prime_p != 2 then q is not prime, take the next prime


    while (mpz_cmp(p, q) == 0) {
        mpz_urandomb(q, state, key_length / 2);
        while (mpz_probab_prime_p(q, 30) < 1) {
            mpz_nextprime(q, q);
        }
    }
    //n = p*q
    mpz_mul(n, p, q);

    //lambda(n) = (p-1) * (q-1)
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lambda, p1, q1);

    do {
        mpz_urandomb(e, state, key_length);  //choose random prime e = key_length
        //make sure the conditions for e are being checked
        mpz_gcd(gcd1, e, lambda); 
        mpz_mod(remainder, e, lambda);
    } while(mpz_cmp_ui(gcd1, 1) != 0 ||  mpz_cmp_ui(remainder, 0) == 0);

    //d is the modular inverse of (e, lambda)
    mpz_invert(d, e, lambda);

    //clearing GMP variables
    mpz_clears(p, q, lambda, p1, q1, gcd1, NULL);
    gmp_randclear(state);
}


void encrypt(char *input_file, char *output_file, char *key_file){
    //opening input file for reading
    FILE *ifile = fopen(input_file, "r");
    //opening output file for writing
    FILE *ofile = fopen(output_file, "w");
    //opening key file for reading
    FILE *kfile = fopen(key_file, "r");

    if(!ifile){
        perror("Sorry!Unable to open input file.");
        return;
    }

    if(!ofile){
        perror("Sorry!Unable to open output file.");
        fclose(ifile);
        return;
    }

    if(!kfile){
        perror("Sorry!Unable to open key file.");
        fclose(ifile);
        fclose(ofile);
        return;
    }

    mpz_t n, e, plaintext, ciphertext;
    mpz_inits(n, e, plaintext, ciphertext, NULL);
    //reading public key (n, e) from key file
    int key_scan = gmp_fscanf(kfile, "%Zd %Zd", n, e);

    //making sure we got both n and e and not eof 
    if(key_scan == EOF){
        fprintf(stderr, "Sorry!Unexpected error reading the file or reached the end of it.");
        fclose(ifile);
        fclose(kfile);
        fclose(ofile);
        mpz_clears(n, e, plaintext, ciphertext, NULL);
        return;
    }else if(key_scan != 2){
        fprintf(stderr, "Sorry!Found less that 2 numbers.");
        fclose(ifile);
        fclose(kfile);
        fclose(ofile);
        mpz_clears(n, e, plaintext, ciphertext, NULL);
        return;
    }

    fclose(kfile);

    int ch;

    //read and encrypt character by character
    while ((ch = fgetc(ifile)) != EOF) {
        mpz_set_ui(plaintext, ch);  //set plaintext to the character's ASCII value

        //encrypt the plaintext
        mpz_powm(ciphertext, plaintext, e, n);

        //write the encrypted character to the output file
        mpz_out_str(ofile, 10, ciphertext);
        fprintf(ofile, "\n");  // Separate each encrypted character by newline
    }

    //closing input file
    fclose(ifile);
    //closing output file
    fclose(ofile);

    mpz_clears(n, e, plaintext, ciphertext, NULL);

}


void decrypt(char *input_file, char *output_file, char *key_file){

    //opening input file for reading
    FILE *ifile = fopen(input_file, "r");
    //opening output file for writing
    FILE *ofile = fopen(output_file, "w");
    //opening key file for reading
    FILE *kfile = fopen(key_file, "r");

    if(!ifile)
        perror("Sorry!Unable to open input file.");

    if(!ofile)
        perror("Sorry!Unable to open output file.");

    if(!kfile)
        perror("Sorry!Unable to open key file.");

    mpz_t n, d, plaintext, ciphertext;
    mpz_inits(n, d, plaintext, ciphertext, NULL);

    //reading private key (n, d) from key file
    int key_scan = gmp_fscanf(kfile, "%Zd %Zd", n, d);

    //making sure we got both n and d and not eof 
    if(key_scan == EOF){
        fprintf(stderr, "Sorry!Unexpected error reading the file or reached the end of it.");
        fclose(ifile);
        fclose(kfile);
        fclose(ofile);
        mpz_clears(n, d, plaintext, ciphertext, NULL);
        return;
    }else if(key_scan != 2){
        fprintf(stderr, "Sorry!Found less that 2 numbers.");
        fclose(ifile);
        fclose(kfile);
        fclose(ofile);
        mpz_clears(n, d, plaintext, ciphertext, NULL);
        return;
    }

    fclose(kfile);

    char buffer[4096];

    while (fgets(buffer, sizeof(buffer), ifile) != NULL) {
        if (mpz_set_str(ciphertext, buffer, 10) != 0) {
            fprintf(stderr, "Error converting ciphertext to number.\n");
            break;
        }

        //decrypt ciphertext
        mpz_powm(plaintext, ciphertext, d, n);

        //turn to ASCII
        int decrypted_char = mpz_get_ui(plaintext);  
        fputc(decrypted_char, ofile);  //write the result in the output file
    }

    //closing input file
    fclose(ifile);
    //closing output file
    fclose(ofile);

    mpz_clears(n, d, ciphertext, plaintext, NULL);
}

void performance_analysis(char *performance_file,  mpz_t n, mpz_t e, mpz_t d){

    FILE *pfile = fopen(performance_file, "w");

    if(!pfile){
        perror("Sorry!Unable to open performance file.");
        return;
    }

    unsigned int key_lengths[] = {1024, 2048, 4096};

    for(int i = 0; i < 3; i++){
    unsigned int key_length = key_lengths[i];
    struct timeval start, end;
    struct rusage usage;

    generateRSAKeyPair(n, e, d, key_length);
    keyStorageFile("public_", key_length, n, e);
    keyStorageFile("private_", key_length, n, d);
    

    getrusage(RUSAGE_SELF, &usage);
    long memory_at_start = usage.ru_maxrss;

    //Encryption time and peak memory usage
    gettimeofday(&start, NULL);
    char public_key_filename[50];
    snprintf(public_key_filename, sizeof(public_key_filename), "public_%u.key", key_length);
    encrypt("plaintext.txt", "encrypted.txt", public_key_filename);
    gettimeofday(&end, NULL);


    getrusage(RUSAGE_SELF, &usage);
    long encryption_memory = usage.ru_maxrss;
    double encryption_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    //Decryption time and peak memory usage
    gettimeofday(&start, NULL);
    char private_key_filename[50];
    snprintf(private_key_filename, sizeof(private_key_filename), "private_%u.key", key_length);
    decrypt("encrypted.txt", "decrypted.txt", private_key_filename);
    gettimeofday(&end, NULL);

    getrusage(RUSAGE_SELF, &usage);
    long decryption_memory = usage.ru_maxrss;
    double decryption_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    fprintf(pfile, "Key Length: %u bits\n", key_length);
    fprintf(pfile, "Encryption Time: %.6f seconds\n", encryption_time);
    fprintf(pfile, "Decryption Time: %.6f seconds\n", decryption_time);
    fprintf(pfile, "Peak Memory Usage (Encryption): %ld Bytes\n", encryption_memory - memory_at_start);        
    fprintf(pfile, "Peak Memory Usage (Decryption): %ld Bytes\n\n", decryption_memory - encryption_memory);

    }

    fclose(pfile);
}

int main(int argc, char *argv[]){

    char *input_file = NULL;
    char *output_file = NULL;
    char *key_file = NULL;
    unsigned int key_length = 0;
    char *performance_file = NULL;

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-i") == 0){
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0){
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0){
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0){
            if(i + 1 < argc){
                key_length = atoi(argv[++i]);
                if(key_length > 0){
                generateRSAKeyPair(n, e, d, key_length);
                keyStorageFile("public_", key_length, n, e);
                keyStorageFile("private_", key_length, n, d);
                } else {
                    fprintf(stderr, "Error! Key length must be greater than 0.\n");
                    return 1;
                }
            } else{
                fprintf(stderr, "Error! Key length is required to proceed with the performance.\n");
                return 1;
            }
        } else if(strcmp(argv[i], "-d") == 0){
                decrypt(input_file, output_file, key_file);
        } else if(strcmp(argv[i], "-e") == 0){
                encrypt(input_file, output_file, key_file);
        } else if(strcmp(argv[i], "-a") == 0){
                performance_file = argv[++i];
                performance_analysis(performance_file, n, e, d);
        } else if(strcmp(argv[i], "-h") == 0){
            printf("Options:\n");
            printf("-i path    Path to the input file (required for -e and -d)\n");
            printf("-o path    Path to the output file (required for -e and -d)\n");
            printf("-k path    Path to the key file (required for -e and -d)\n");
            printf("-g length  Perform RSA key-pair generation given a key length \"length\"\n");
            printf("-d         Decrypt input and store results to output.\n");
            printf("-e         Encrypt input and store results to output.\n");
            printf("-a         Compare the performance of RSA encryption and decryption with three different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n");

        } else {
            fprintf(stderr, "Error! Unknown option.\n");
            return 1;
        }
    }
    mpz_clears(n, e, d, NULL);
    return 0;
}