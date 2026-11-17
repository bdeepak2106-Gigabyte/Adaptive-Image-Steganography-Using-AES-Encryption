# Adaptive Image Steganography Using AES Encryption

## 📌 Project Overview

Adaptive Image Steganography is a Java-based desktop application designed to hide secret messages inside digital images. It uses the Adaptive Least Significant Bit (LSB) technique to select high-contrast regions of an image for hiding information.

The application combines image steganography with AES encryption and SHA-256-based password key generation to provide an additional layer of message security. It also includes a graphical user interface developed using Java Swing.

## 🚀 Features

- **Adaptive LSB Steganography:** Selects high-contrast pixels for hiding secret messages.
- **Normal LSB Steganography:** Supports traditional sequential pixel-based message hiding.
- **AES-128 Encryption:** Encrypts secret messages before embedding them into images.
- **SHA-256 Key Generation:** Generates an AES key from the user's password.
- **Message Hiding:** Embeds secret text inside digital images.
- **Message Extraction:** Retrieves hidden messages using the application.
- **Image Capacity Calculation:** Displays available message storage capacity.
- **Technical Visualization:** Compares Normal LSB and Adaptive LSB pixel selection.
- **Java Swing GUI:** Provides an easy-to-use desktop interface.
- **PNG Image Output:** Saves images containing hidden messages.

## 🛠️ Technologies Used

- Java
- Java Swing
- Image Processing
- Least Significant Bit (LSB)
- Adaptive LSB
- AES-128 Encryption
- SHA-256 Hashing
- Java Cryptography Architecture (JCA)
- Java ImageIO

## ⚙️ Project Modules

1. Image Selection Module
2. Message Hiding Module
3. Adaptive LSB Module
4. AES Encryption Module
5. Password-Based Key Generation Module
6. Message Extraction Module
7. Technical Visualization Module

## 💻 How to Run the Project

**Requirements:**
- Java Development Kit (JDK)
- Windows / Linux operating system

**Steps:**

1. Download or clone this repository.
2. Open the project folder in Command Prompt or Terminal.
3. Compile the Java file:

   `javac SteganographyApp.java`

4. Run the application:

   `java SteganographyApp`

## 🔐 How It Works

1. Select an image from your computer.
2. Enter the secret message.
3. Optionally enter a password for encryption.
4. Select Adaptive LSB or Normal LSB.
5. Hide the message and save the output as a PNG image.
6. To retrieve the message, select the generated image and enter the correct password if encryption was used.
7. The application extracts and displays the hidden message.

## 🎯 Project Objective

The main objective of this project is to demonstrate secure data hiding using image steganography. By implementing Adaptive LSB along with AES encryption, the project explores an additional approach to concealing information within digital images.

## 👨‍💻 Developer

**B. Deepak**

B.Sc Computer Science – Cyber Security Specialization

SRM Institute of Science and Technology, Ramapuram

## 📚 Disclaimer

This project is developed for educational and cybersecurity learning purposes. The current AES implementation is a demonstration and is not recommended for protecting sensitive real-world information.
