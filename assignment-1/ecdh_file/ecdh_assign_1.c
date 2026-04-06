#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <getopt.h>
#include <string.h>

//Print data in hexadecimal format
void hex_format(const char *label, const unsigned char *data, size_t length) {
    printf("%s", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]); //Prints each byte of data as two hexadecimal characters
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
  //Initialize libsodium
  if(sodium_init() < 0){
    printf("libsodium couldn't be initialized.\n");
    return 1;
  } 

  char *output_file = NULL;
  unsigned char a_private_k[crypto_scalarmult_SCALARBYTES], b_private_k[crypto_scalarmult_SCALARBYTES];
  unsigned char a_public_k[crypto_scalarmult_BYTES], b_public_k[crypto_scalarmult_BYTES];
  unsigned char shared_secret_a[crypto_scalarmult_BYTES], shared_secret_b[crypto_scalarmult_BYTES];

  int opt;
  unsigned long long a_pr_input=0, b_pr_input=0;
  int a_provided_k=0, b_provided_k=0;

  while((opt=getopt(argc, argv, "o:a:b:h")) != -1){
    switch(opt){
      case 'o': // -o option: output file name
          output_file = optarg;
          break;
      case 'a': // -a option: Alice's private key
          a_pr_input = strtoull(optarg, NULL, 10);
          a_provided_k = 1;
          break;
      case 'b': // -b option: Bob's private key
          b_pr_input =  strtoull(optarg, NULL, 10);
          b_provided_k = 1;
          break;
      case 'h': // -h option: show help message
          printf("Help message: %s -o <output_file> [-a <a_private_k] [-b <b_private_k]\n", argv[0]);
          break;
      default:
          printf("Invalid argument. Use -h for help.\n");
          exit(1);

    }
  }

  //Generate Alice's key
  if(a_provided_k){
    printf("Using provided Alice's private key: %llu\n", a_pr_input);
    memset(a_private_k, 0, crypto_scalarmult_SCALARBYTES);  // Zero-pad
    for(int i = 0; i<crypto_scalarmult_SCALARBYTES; i++){
        a_private_k[i] = (a_pr_input >> (i*8)) & 0xFF;
    }
  }else{
    randombytes_buf(a_private_k, crypto_scalarmult_SCALARBYTES);
    printf("Generated random Alice's private key.\n");
  }

  //Elliptic curve point computation for Alice's key
  crypto_scalarmult_base(a_public_k, a_private_k);

  //Generate Bob's key
  if(b_provided_k){
    printf("Using provided Bob's private key: %llu\n", b_pr_input);
    memset(b_private_k, 0, crypto_scalarmult_SCALARBYTES);  // Zero-pad
    for(int i = 0; i<crypto_scalarmult_SCALARBYTES; i++){
        b_private_k[i] = (b_pr_input >> (i*8)) & 0xFF;
    }
  }else{
    randombytes_buf(b_private_k, crypto_scalarmult_SCALARBYTES);
    printf("Generated random Bob's private key.\n");
  }

  //Elliptic curve point computation for Bob's key
  crypto_scalarmult_base(b_public_k, b_private_k);

  //Shared secret Computation
  if (crypto_scalarmult(shared_secret_a, a_private_k, b_public_k) != 0) {
      printf("Failed to compute shared secret for Alice.\n");
      return 1;
  }
  if (crypto_scalarmult(shared_secret_b, b_private_k, a_public_k) != 0) {
      printf("Failed to compute shared secret for Bob.\n");
      return 1;
  }

  //Print public keys and shared secrets in hexadecimal format
  hex_format("Alice's public key: ", a_public_k, crypto_scalarmult_BYTES);
  hex_format("Bob's public key: ", b_public_k, crypto_scalarmult_BYTES);
  hex_format("Alice's shared secret: ", shared_secret_a, crypto_scalarmult_BYTES);
  hex_format("Bob's shared secret: ", shared_secret_b, crypto_scalarmult_BYTES);

  //Check if shared sectrets match. If they do, the key exchange is successful
  if ( memcmp(shared_secret_a, shared_secret_b, (size_t)crypto_scalarmult_BYTES)==0){
      printf("Successful key exchange!\n");
  }else{
      printf("Key exchange failed...\n");
  }

  // Write to output file
if (output_file) {
    FILE *f = fopen(output_file, "w");
    if (!f) {
        perror("Sorry! Unable to open output file.");
        return 1;
    }

    // Write Alice's public key 
    fprintf(f, "Alice's public key: \n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(f, "%02x", a_public_k[i]);
    }
    fprintf(f, "\n");

    // Write Bob's public key 
    fprintf(f, "Bob's public key: \n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(f, "%02x", b_public_k[i]);
    }
    fprintf(f, "\n");

    // Write Alice's shared secret 
    fprintf(f, "Alice's shared secret: \n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(f, "%02x", shared_secret_a[i]); // Ensure this loop is correct
    }
    fprintf(f, "\n");

    // Write Bob's shared secret 
    fprintf(f, "Bob's shared secret: \n");
    for (size_t i = 0; i < crypto_scalarmult_BYTES; i++) {
        fprintf(f, "%02x", shared_secret_b[i]);
    }
    fprintf(f, "\n");

    fclose(f);
    printf("Results written to %s\n", output_file);
}

  return 0;

}
