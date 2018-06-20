#include "crypto_example.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto32MT.lib")

using std::string;
using std::cin;

int main() {
  Crypto crypto;

  printKeys(&crypto);

  while(!std::cin.eof())
  {
    encryptRsa(&crypto);
  }

  return 0;
}

void encryptRsa(Crypto* crypto)
{
  string message = getMessage("Message to RSA encrypt: ");

  // Encrypt the message with RSA
  // +1 on the string length argument because we want to encrypt the NUL terminator too
  unsigned char* encryptedMessage = NULL;
  unsigned char* encryptedKey;
  unsigned char* iv;
  size_t encryptedKeyLength;
  size_t ivLength;

  int encryptedMessageLength = crypto->rsaEncrypt((const unsigned char*)message.c_str(), message.size()+1,
    &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv, &ivLength);

  if(encryptedMessageLength == -1)
  {
    fprintf(stderr, "Encryption failed\n");
    return;
  }

  // Print the encrypted message as a base64 string
  char* b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
  printf("Encrypted message: %s\n", b64Message);

  // Decrypt the message
  char *decryptedMessage = NULL;

  int decryptedMessageLength = crypto->rsaDecrypt(encryptedMessage, (size_t)encryptedMessageLength,
    encryptedKey, encryptedKeyLength, iv, ivLength, (unsigned char**)&decryptedMessage);

  if(decryptedMessageLength == -1)
  {
    fprintf(stderr, "Decryption failed\n");
    return;
  }

  printf("Decrypted message: %s\n", decryptedMessage);

  // Clean up
  free(encryptedMessage);
  free(decryptedMessage);
  free(encryptedKey);
  free(iv);
  free(b64Message);

  encryptedMessage = NULL;
  decryptedMessage = NULL;
  encryptedKey = NULL;
  iv = NULL;
  b64Message = NULL;
}

string getMessage(const char *prompt)
{
  string message;

  printf(prompt);
  fflush(stdout);

  getline(std::cin, message);
  return message;
}

void printKeys(Crypto *crypto)
{
  // Write the RSA keys to stdout
  crypto->writeKeyToFile(stdout, KEY_SERVER_PRI);
  crypto->writeKeyToFile(stdout, KEY_SERVER_PUB);
  crypto->writeKeyToFile(stdout, KEY_CLIENT_PUB);
}

void printBytesAsHex(unsigned char *bytes, size_t length, const char *message)
{
  printf("%s: ", message);

  for(unsigned int i = 0; i < length; i++)
  {
    printf("%02hhx", bytes[i]);
  }

  puts("");
}
