# SECURE EMAIL
Using the crytopgraphy python library, we implement a secure email system which satisfies
the CIA triad of Confidentiality, Integrity, and Authenticity through the use of various 
cryptographic algorithms such as symmetric ciphers, message digests, and RSA public key 
encryption.
Given an email message from User A to User B, we use message digest algorithm, encryption algorithm
and the public/private key pairs of users to generate a security-enhanced output message that will handle:
(a) Confidentiality
(b) Authentication/Integrity and,
(c) Authentication/Integrity and Confidentiality. 

## Setup Instructions
```
sudo apt install python3
sudo apt install python3-pip
pip3 install cryptography==3.3.1
```

## Running Code
The file usernames.txt contains a users list and Mail-sample.txt is a sample mail which needs to be secured.
```
pico usernames.txt
./lab2 CreateKeys usernames.txt 2048
pico Mail-sample.txt
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 2048
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt
```

**NOTE**: 

* The script.sh file quickly goes through all the possible * combinations to ensure there are no errors or differences between decrypted mail output and sample mail. If running the script, please make sure usernames include Alice and Bob. 
* In a real world scenario users keys are stored in a database by a trusted third party but here we store them locally for ease of implementation.
* In some cases, diff command does show a difference of a new line being added at the end of the decrypted mail but otherwise the message content is recovered efficiently.
