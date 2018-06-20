#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#ifndef CRYPTO_H
#define CRYPTO_H

#define RSA_KEYLEN 2048

#define PSEUDO_CLIENT

#define SUCCESS 0
#define FAILURE -1

#define KEY_SERVER_PRI 0
#define KEY_SERVER_PUB 1
#define KEY_CLIENT_PUB 2

class Crypto
{
public:
  Crypto();
  Crypto(unsigned char* remotePubKey, size_t remotePubKeyLen);
  ~Crypto();

  int rsaEncrypt(
    const unsigned char *message,
    size_t messageLength,
    unsigned char **encryptedMessage,
    unsigned char **encryptedKey,
    size_t *encryptedKeyLength,
    unsigned char **iv,
    size_t *ivLength);

  int rsaDecrypt(
    unsigned char *encryptedMessage,
    size_t encryptedMessageLength,
    unsigned char *encryptedKey,
    size_t encryptedKeyLength,
    unsigned char *iv,
    size_t ivLength,
    unsigned char **decryptedMessage);

  int getRemotePublicKey(unsigned char **publicKey);
  int setRemotePublicKey(unsigned char *publicKey, size_t publicKeyLength);

  int getLocalPublicKey(unsigned char **publicKey);
  int getLocalPrivateKey(unsigned char **privateKey);

  int writeKeyToFile(FILE *file, int key);

private:
  static EVP_PKEY *localKeypair;
  EVP_PKEY *remotePublicKey;

  EVP_CIPHER_CTX *rsaEncryptContext;

  EVP_CIPHER_CTX *rsaDecryptContext;

  int init();
  int generateRsaKeypair(EVP_PKEY **keypair);
  int bioToString(BIO *bio, unsigned char **string);
};

#endif
