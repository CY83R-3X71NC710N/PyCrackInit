
# PyCrackInit 

PyCrackInit is an AES256 encryption/decryption library in Python. This library is built with the PyCrypto library and uses the CBC/CFB modes of block cipher with HMAC-SHA256 as the message authentication code. Secure random is also included in this library. This library provides enhanced security through the use of key stretching with the PBKDF2 algorithm.  

# About

PyCrackInit stands for Python Crack Initialize. Developed for cyber security engineers and professionals, PyCrackInit takes us a step further into the world of cryptography to protect our data from malicious actors. 

PyCrackInit uses various encryption techniques in order to secure our data, namely AES256 encryption/decryption and HMAC-SHA256 as the message authentication code. This library also provides enhanced security through the use of key stretching with the PBKDF2 algorithm. Additionally, a secure random is included in this library.

## Table of Contents
* [About](#about)
* [Goals](#goals)
* [Functionality](#functionality)
* [Installation](#installation)
* [Usage](#usage)
* [Tests](#tests)
* [Development](#development)
* [Screenshots](#screenshots)
* [Acknowledgements](#acknowledgements)
* [License](#license)

## Goals
1. Create an AES256 encryption/decryption library in Python using the PyCrypto library with CBC/CFB modes of block cipher and HMAC-SHA256 as the Message Authentication Code
2. Utilize key stretching with the PBKDF2 algorithm to provide enhanced security
3. Include a secure random
4. Build the library with a user-friendly interface and intuitive design
5. Create unit tests and integration tests to ensure correctness
6. Make the code extendable and easily maintainable
7. Create up-to-date documentation
8. Use advanced markdown to make the project look unique
9. Provide a lightweight framework and any tools to enhance security
10. Make the README.md over 1000 lines long and include goals, roadmaps, what the project should become and more

## Functionality
PyCrackInit can be used to encrypt messages, files, images and other data with AES256 encryption. The encryption process in PyCrackInit is made secure by the usage of the PBKDF2 algorithm for key stretching and HMAC-SHA256 for authentication. In addition, the library supports CBC/CFB modes of block cipher in order to ensure the encryption is secure. 

PyCrackInit also provides a secure random function to ensure that the generated keys are secure and unguessable. The secure random generator is also used in the encryption/decryption process to ensure that the encrypted data is secure from brute force attacks.

## Installation
To install the PyCrackInit library, open up a command line interface and enter: 

```
pip install pycrackinit
```

Once PyCrackInit is installed, you need to import it into your project:

```
import pycrackinit
```

## Usage
Once the library is imported, you can call the methods to start encrypting data. Here is an example of how to encrypt a file with AES256:

```python
# Import PyCrackInit
import pycrackinit

# Create a new AES256 key
aes_key = pycrackinit.create_key(256)

# Encrypt the file
pycrackinit.encrypt_file(filepath, aes_key)
```

You can find the full list of supported functionalities in the [documentation](#).

## Tests
To ensure correctness, we have created unit tests and integration tests for all of the methods included in the library. Our tests ensure all known security and cryptography vulnerabilities are taken care of.

## Development
We are always looking for new contributors to help us build out the library and make it more secure. If you would like to contribute, please fork the repository and create a pull request with your changes. 

## Screenshots
Here is a screenshot of the encrypted file. Notice the encryption key that is used to encrypt the file:

![screenshot](screenshot.png)

## Acknowledgements
We would like to thank the Python community for their support. We would also like to thank [PyCrypto](#) for providing the tools needed to build this library.

## License
The PyCrackInit software is licensed under the [MIT License](LICENSE). The license text is available in the root of this repository. 

CY83R-3X71NC710N ©2023
