---

# Secure Password Storage Protocol

This protocol provides a way to securely store passwords on a server such that they can be retrieved by authorized clients, but are not accessible to the server or to unauthorized parties. The protocol uses a combination of public-key cryptography, symmetric-key cryptography, and key derivation functions to provide multiple layers of security.

## Protocol Overview

The protocol consists of the following steps:

1. Client Creation
	* The client generates a Kyber key pair and a Dilithium key pair, and sends the public parts to the server.
	* The client hashes the master password using Argon2id, and uses the output as the seed for the Kyber and Dilithium key pairs. The server stores the public parts and the salt.
2. Authentication
	* Shards
		+ The client must provide at least 3 shards to reconstruct the Kyber and Dilithium key pairs.
		+ The server sends a challenge to the client, which the client signs using the Dilithium key pair and returns to the server for verification.
	* Master Password
		+ The client receives the salt from the server and reconstitutes the Kyber and Dilithium key pairs.
		+ The server sends a challenge to the client, which the client signs using the Dilithium key pair and returns to the server for verification.
3. Encrypted Communication
	* The server encapsulates the client's public key and sends the client a ciphertext that the client decapsulates to communicate securely.
4. Password Storage
	* The client encrypts the password using Blake3 with the Kyber key pair's private part, and then encrypts the result using XChaChaPoly1305 with a shared secret. The client sends the nonce to the server over TLS.
	* The server encrypts the password using a unique key derived from the client's public Kyber key, and stores the encrypted password and nonce in the database.
5. Password Retrieval
	* The server retrieves the encrypted password and nonce from the database, decrypts the password using the unique key, and re-encrypts it using XChaChaPoly1305 with the shared secret. The server sends the nonce and ciphertext to the client over TLS.
	* The client decrypts the ciphertext using the shared secret and then decrypts the result using the Kyber key pair's private part.

## Protocol Details

### Client Creation

The client generates a Kyber key pair and a Dilithium key pair using the `kyber` and `dilithium` libraries, respectively. The client sends the public parts of the key pairs to the server, which stores them in the database.

The client also hashes the master password using Argon2id with the `argon2` library, and uses the output as the seed for the Kyber and Dilithium key pairs. The server stores the salt used for the Argon2id hash.

### Authentication

To authenticate, the client must provide at least 3 shards of the Kyber and Dilithium key pairs. The server sends a challenge to the client, which the client signs using the Dilithium key pair and returns to the server for verification.

Alternatively, the client can authenticate using the master password. The client receives the salt from the server, reconstitutes the Kyber and Dilithium key pairs using the hashed password as the seed, and signs a challenge from the server using the Dilithium key pair.

### Encrypted Communication

Once the client is authenticated, the server encapsulates the client's public key using the `box_` library and sends the client a ciphertext that the client decapsulates to communicate securely.

### Password Storage

To store a password, the client first encrypts the password using Blake3 with the Kyber key pair's private part, using the `blake3` library. The client then encrypts the result using XChaChaPoly1305 with a shared secret, using the `xchacha20poly1305` library. The client sends the nonce used for the XChaChaPoly1305 encryption to the server over TLS.

The server encrypts the password using a unique key derived from the client's public Kyber key using the `hkdf` library, and stores the encrypted password and nonce in the database.

### Password Retrieval

To retrieve a password, the server retrieves the encrypted password and nonce from the database, decrypts the password using the unique key, and re-encrypts it using XChaChaPoly1305 with the shared secret. The server sends the nonce and ciphertext to the client over TLS.

The client decrypts the ciphertext using the shared secret and then decrypts the result using the Kyber key pair's private part.

## Key Rotation

The server periodically rotates the server-side secret and re-encrypts all user data with a new key. The rotation period can be adjusted based on the specific security requirements of the use case.

## Security Considerations

The protocol provides multiple layers of security to protect against various types of attacks:

* Public-key cryptography protects against passive attacks, such as eavesdropping on network traffic.
* Symmetric-key cryptography protects against active attacks, such as man-in-the-middle attacks.
* Key derivation functions protect against attacks on the master password, such as brute-force attacks.
* Sharding the Kyber and Dilithium key pairs provides protection against key compromise, as an attacker would need to compromise multiple shards to reconstruct the key pairs.
* Periodic rotation of the server-side secret provides protection against key compromise, as an attacker would need to compromise the server during the rotation period to access user data.

However, the protocol is not foolproof and cannot protect against all types of attacks. It is important to follow best practices for secure development, such as keeping software up to date, using secure random number generators, and limiting exposure of sensitive data.

## Conclusion

This protocol provides a secure way to store passwords on a server such that they can be retrieved by authorized clients, but are not accessible to the server or to unauthorized parties. By using a combination of public-key cryptography, symmetric-key cryptography, and key derivation functions, the protocol provides multiple layers of security to protect against various types of attacks. However, it is important to follow best practices for secure development and to consult with a security expert to ensure that the protocol is appropriate for the specific use case.
