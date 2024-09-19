# cryptoooor

<a href="https://ko-fi.com/pindjouf" class="kofi-button" target="_blank">Support me on Ko-fi</a>

> [!WARNING]
> This is a very rough MVP, a new release with more security and ease of use is in the works

*cryptoooor* is a command-line tool for encrypting and decrypting files using AES-256-GCM encryption. It allows users to securely encrypt files and then decrypt them later using a derived key.

## Features

- AES-256-GCM encryption for secure file encryption.
- Automatic key generation and key derivation using the Scrypt algorithm.
- Support for encrypting and decrypting files via simple command-line arguments.
- Handles binary files securely without corrupting the contents.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/cryptoooor.git
   cd cryptoooor
   ```

2. Build the project using Cargo:

   ```bash
   cargo build --release
   ```

3. Run the executable:

   ```bash
   ./target/release/cryptoooor
   ```

## Usage

### Encrypt a file

To encrypt a file, run the following command:

```bash
cryptoooor myfile.txt
```

This will generate an encrypted file with the `.bin` extension, e.g., `myfile.bin`.

### Decrypt a file

To decrypt a previously encrypted file, run the following command:

```bash
cryptoooor -d myfile.bin
```

This will decrypt the file and save the output with the `.dec` extension, e.g., `myfile.dec`.

### Flags

- `-d, --decrypt` : Decrypts the specified `.bin` file.

## How It Works

### Key Derivation

*cryptoooor* uses the [Scrypt](https://en.wikipedia.org/wiki/Scrypt) algorithm for key derivation. It generates a key using a password that is hashed with a salt, ensuring that each key is unique for a given password-salt pair.

### Encryption

AES-256-GCM is used to securely encrypt the contents of files. The ciphertext and nonce are stored together, and both are required to decrypt the file.

### Decryption

The nonce and key are used to decrypt the file and recover the original contents.

## Roadmap

- [ ] **Improved Security Features**: Enhancing the encryption algorithm and key management for better security.
- [ ] **User-Friendly Enhancements**: Adding a progress bar to provide visual feedback during encryption and decryption processes.
- [ ] **Extended File Support**: Implementing support for additional file formats and larger files.
- [x] **Web app**: Make cryptoooor available on the web.

## Contributing

Feel free to contribute by submitting issues or pull requests.

## License

This project is licensed under the MIT License.
