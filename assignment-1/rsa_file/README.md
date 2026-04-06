# RSA Encryption and Decryption
This code implements RSA key-pair generation algorithm using GNU Multiple Precision Arithmetic Library(GMP). 
The program can generate key pairs, encrypt, decrypt files and analyze performance for different key lengths.

# Requirements
- GCC (GNU Compiler Collection)
- GMP library (install using your package manager, e.g., `sudo apt-get install libgmp-dev`)

# Compilation
-`gcc -o rsa_assign_1 rsa_assign_1.c -lgmp`: run this command to your terminal to compile the code or the command `make` to run the Makefile for compilation.

# Run the compiled program
-`./rsa_assign_1 -g 1024`: used to generate RSA key pair(can also run for 2048, 4096)
-`./rsa_assign_1 -i plaintext.txt -o encrypted.txt -k public_1024.key -e`: used to encrypt a file (can also run for 2048, 4096)
-`./rsa_assign_1 -i encrypted.txt -o decrypted.txt -k private_1024.key -d`: used to decrypt a file (can also run for 2048, 4096)
-`./rsa_assign_1 -a performance.txt`: used to get the performance analysis

# Other command line options
The program can be run with some other options, by running in the terminal the command: `./rsa_assign_1 [options]`, where the options are the following:
-i path : Specify the path to the input file (required for encryption and decryption).
-o path : Specify the path to the output file (required for encryption and decryption).
-k path : Specify the path to the key file (required for encryption and decryption).
-g length: Generate RSA key-pair with the specified key length (must be greater than 0).
-d : Decrypt the input file and store results in the output file.
-e : Encrypt the input file and store results in the output file.
-a path : Perform a performance analysis and save results in the specified path.
-h : Display help information.