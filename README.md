# Diffie_Hellman_Encryption
This is a library that generates keys and does  encryption and decryption using the DIffie Hellman key exchange

This is dependant on RUST being installed

Rust can be installed by following these instructions:

	https://www.rust-lang.org/tools/install

Or on Mac OS X using this curl command:

	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 

<br>

Building the Console Application
=====================================================================================================================================================================
To build or run a new exectuable Rust must be installed.
- ## Build an executable
    - In the project directory run the following commands to build to the target directory which will generate library that can be use as a C dll
  - ``` cargo build ```
  <br>

Functions
=====================================================================================================================================================================

- ## generate_public_key
  - Generate a private and public key returned as a space seperated string. The key is generated from OS rnadomness.

- ## generate_shared_key
  - Generates a shared key using the Diffie Hellman key exchange, by providing your private key and providing the public key of the other party involved in the key exchange. The key is returned as a string

- ## encrypt_data
  - Encrypts a string provided with a key that is also provided. The key provided should be the shared key generate from the Diffie Hellman exchange to ensure the other party is able to decrype the data.

- ## decrypt_data
  - Decrypts a string provided with a key that is also provided. The key provided should be the shared key generate from the Diffie Hellman exchange.