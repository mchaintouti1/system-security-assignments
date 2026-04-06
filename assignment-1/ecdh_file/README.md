# Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
This code demonstrates a simple Elliptic Curve Diffie-Hellman (ECDH) Key Exchange using the libsodium(https://libsodium.gitbook.io/doc/) library.
It basically allows two parties to securely establish a shared secret over an insecure communication channel.It generates public-private key pairs
 for Alice and Bod,computes shared secrets and allows for the use of custom private keys as input.
The public keys and the shared secrets are printed to the console and written to an output file.

# Requirements
-`libsodium` : Here are some instructions on how to install the library (https://doc.libsodium.org/installation)
-`gcc` (or any C compiler)

# Compilation
-`gcc -o ecdh_assign_1 ecdh_assign_1.c -lsodium`: run this command to your terminal to compile the code or the command `make` to run the Makefile for compilation.

# Run the compiled program
Here we have two ways on how to run the program:
-`./ecdh_assign_1 -o ecdh.txt1`: this command is for random private keys' generation for Alice and Bod.
-`./ecdh_assign_1 -o ecdh.txt2 -a 5 -b 3`: now the private keys are provided 

# Other command line options
-o option: output file name
-a number: Alice's private key
-b number: Bob's private key 
-h option: This help message