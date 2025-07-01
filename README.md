# Secure Agent Messaging System

This project was developed as part of a group coursework for the MSc Computer Science module on Cybersecurity at the University of Leicester. It showcases a Java-based secure client-server messaging system using cryptographic techniques such as RSA, SHA256withRSA signatures, and message confidentiality.

## 🔐 Features

- Client-server architecture using Java sockets
- RSA encryption and decryption with `RSA/ECB/PKCS1Padding`
- SHA256withRSA digital signatures
- MD5-hashed user IDs for anonymous message storage
- Time-stamped messages to prevent replay and ensure traceability
- Signature verification for message integrity and authenticity

## 📁 Project Structure

```
SecureAgentMessagingSystem/
├── Client.java               # The client-side application
├── Server.java               # The server-side application
├── keyGenerationRSA.java            # Utility for generating RSA key pairs
├── Lad.prv                 # Sample public/private key files (one per user)
├── server.prv   # Server's key files
├── README.md
```

## 🧪 How It Works

### Message Retrieval:
1. The client connects and sends a **hashed user ID**.
2. The server looks up messages for that hash.
3. The server sends encrypted messages along with timestamps and signatures.
4. The client:
   - Verifies the signature using the server's public key.
   - Decrypts the message using their private key.
   - Displays the timestamp and plaintext.

### Message Sending:
1. The client encrypts a message (including recipient ID) using the **server's public key**.
2. The client signs the encrypted message + timestamp using its **private key**.
3. The client sends: unhashed sender ID, encrypted message, timestamp, and signature.
4. The server:
   - Verifies the signature using the sender’s public key.
   - Decrypts to extract the recipient ID and message.
   - Encrypts the message using the recipient’s public key.
   - Stores it using a hashed recipient ID.

## ▶️ How to Compile and Run (Windows)

1. Open Command Prompt and navigate to the project folder:

```
cd C:\Path\To\SecureAgentMessagingSystem
```

2. Compile all Java files:

```
javac *.java
```

3. Start the server:

```
java Server 8888
```

4. In another terminal, start the client:

```
java Client localhost 8888 Vivek
```

## 🧾 Notes

- RSA key pairs should be pre-generated and placed in the working directory.
- The server does **not** persist data—message storage is in-memory.
- The client retrieves **all available messages** on startup.
- Signature validation includes both the **encrypted message and timestamp**.

## 📜 License

This project is for educational use as part of the University of Leicester MSc program. You may reuse or modify it under the [MIT License](https://opensource.org/licenses/MIT).

> ⚠️ **Disclaimer:** This project was submitted as university coursework. It is published here for educational and portfolio purposes only. Please do not reuse this code for academic submissions.
