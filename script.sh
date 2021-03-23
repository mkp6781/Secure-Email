#!/bin/sh

./lab2 CreateKeys usernames.txt 1024
./lab2 CreateKeys usernames.txt 2048

echo "======================================================================================"
echo "-----------------------------  CONFIDENTIALITY ONLY  ---------------------------------"
echo "======================================================================================"

echo "sha512 des-ede3-cbc 1024"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 1024
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 des-ede3-cbc 2048"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 2048
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 1024"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 1024
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 2048"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 2048
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 1024"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 1024
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 2048"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 2048
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 des-ede3-cbc 1024"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 1024
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 des-ede3-cbc 2048"
./lab2 CreateMail CONF Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 2048
./lab2 ReadMail CONF Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "======================================================================================"
echo "----------------------- AUTHENTICATION AND INTEGRITY ONLY ----------------------------"
echo "======================================================================================"
 
echo "sha512 des-ede3-cbc 1024"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 1024
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 des-ede3-cbc 2048"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 2048
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 1024"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 1024
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 2048"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 2048
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 1024"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 1024
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 2048"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 2048
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 des-ede3-cbc 1024"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 1024
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "echo sha3-512 des-ede3-cbc 2048"
./lab2 CreateMail AUIN Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 2048
./lab2 ReadMail AUIN Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt


echo "======================================================================================"
echo "----------------- CONFIDENTIALITY, AUTHENTICATION AND INTEGRITY ONLY -----------------"
echo "======================================================================================"

echo "sha512 des-ede3-cbc 1024"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 1024
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 des-ede3-cbc 2048"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha512 des-ede3-cbc 2048
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 1024"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 1024
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha512 aes-256-cbc 2048"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha512 aes-256-cbc 2048
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 1024"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 1024
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 aes-256-cbc 2048"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha3-512 aes-256-cbc 2048
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 aes-256-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 des-ede3-cbc 1024"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 1024
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 1024
diff Mail-sample.txt Mail-decrypt.txt

echo "sha3-512 des-ede3-cbc 2048"
./lab2 CreateMail COAI Alice Bob Mail-sample.txt Mail-out.txt sha3-512 des-ede3-cbc 2048
./lab2 ReadMail COAI Alice Bob Mail-out.txt Mail-decrypt.txt sha3-512 des-ede3-cbc 2048
diff Mail-sample.txt Mail-decrypt.txt