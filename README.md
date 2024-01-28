# YubiKey RSA Encryption and Decryption CLI Tool

## Description

This CLI tool provides an interface to interact with a YubiKey for RSA-KEM (using AES-GCM) encryption, decryption, and key management. It allows encrypting and decrypting files using the YubiKey's RSA capabilities and supports key generation and extraction.

## Installation

Download the appropriate binary for your OS from the latest GitHub release and add it to your system path.

## Usage

- **Encrypt a File**

```bash
  yubikey_encrypt encrypt --input path/to/file --output path/to/encrypted.enc
```
  
- **Decrypt a File**

```bash
yubikey_encrypt decrypt --input path/to/encrypted.enc --output path/to/decrypted
```

- **Generate RSA Key**

```bash
yubikey_encrypt generate-key [--length 1024|2048]
```

Default length is for the RSA keys is 2048 bits.

- **Extract RSA Public Key**

```bash
yubikey_encrypt extract-key
```

Displays the public key in PEM format.

## Security Warning

No security audits of this crate have ever been performed. Presently it is in an experimental stage and may still contain high-severity issues.

USE AT YOUR OWN RISK!

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes.

## License

This project is licensed under MIT License - see the LICENSE file for details.

---

*Note: This tool requires a modern YubiKey device. Ensure your YubiKey is properly set up and connected to your machine before using this tool.*
