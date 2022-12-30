#include <Crypto.h>
#include <base64.hpp>

#define AES_BLOCK_SIZE 16
#define HEADER_SIZE 32          //Used for the final iot message header. 32 bytes = 256 bits


uint8_t key[AES_BLOCK_SIZE] = { 0x1C,0x3E,0x4B,0xAF,0x13,0x4A,0x89,0xC3,0xF3,0x87,0x4F,0xBC,0xD7,0xF3, 0x31, 0x31 };
uint8_t iv[AES_BLOCK_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


// IoT Resource paremeters Generate the Header (private tag)
  const byte privateID_s[SHA256_SIZE]    = { 0x4e, 0x89, 0xd2, 0x11, 0x5f, 0x57, 0xb4, 0xa5, 0xf1, 0x13, 0xe6, 0x25, 0x77, 0xfc, 0xc0, 0x8d, 0x30, 0xea, 0x59, 0x4c, 0xb6, 0x88, 0xa3, 0x9f, 0xfc, 0x69, 0xe6, 0x88, 0x9f, 0x56, 0x9b, 0x8b };
  const byte privateID_f[SHA256_SIZE]    = { 0xc0, 0x8d, 0x30, 0xea, 0x9b, 0xde, 0x7f, 0x8b, 0x52, 0x8b, 0xcd, 0x57, 0xb4, 0xa5, 0xf1, 0x13, 0xe6, 0x25, 0x77, 0xd2, 0x11, 0xb4, 0xa5, 0xf1, 0x13, 0xe6, 0x25, 0x77, 0xfc, 0xc0, 0x8d, 0xfc };
  byte privateTag[SHA256_SIZE] = { 0x8c, 0xb4, 0xaa, 0x59, 0x4c, 0xb6, 0x88, 0xa3, 0x9f, 0xfc, 0x69, 0xe6, 0x88, 0x9f, 0x56, 0xdd, 0xa4, 0x4c, 0xcc, 0x5f, 0x57, 0xb4, 0xa5, 0xf1, 0x13, 0xe6, 0x25, 0x77, 0xfc, 0x88, 0x77, 0xfc };

// Public time parameters
unsigned long timeBegin, timeEnd, duration;
double averageDuration;

          

void bufferSize(char* text, int &length)
{
  int i = strlen(text);
  int buf = round(i / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  length = (buf <= i) ? buf + AES_BLOCK_SIZE : length = buf;
}
    
void encrypt(char* plain_text, char* output, int length)
{
  byte enciphered[length];
  //RNG::fill(iv, AES_BLOCK_SIZE); 
  AES aesEncryptor(key, iv, AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
  aesEncryptor.process((uint8_t*)plain_text, enciphered, length);
  int encrypted_size = sizeof(enciphered);
  char encoded[encrypted_size];
  encode_base64(enciphered, encrypted_size, (unsigned char*)encoded);
  strcpy(output, encoded);
}

void decrypt(char* enciphered, char* output, int length)
{
  length = length + 1; //re-adjust
  char decoded[length];
  decode_base64((unsigned char*)enciphered, (unsigned char*)decoded);
  bufferSize(enciphered, length);
  byte deciphered[length];
  AES aesDecryptor(key, iv, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
  aesDecryptor.process((uint8_t*)decoded, deciphered, length);
  strcpy(output, (char*)deciphered);
}

void setup()
{
  // Setup Serial
  Serial.begin(115200);
  delay(500);
  Serial.println("LaMReD Private IoT Tuple Test");
  Serial.println("-----------------------------");
  Serial.println("*****************************");

}


void loop() {

  Serial.println();
  char resourceAddress[] = "http://test.com";
  byte privateTag_new[SHA256_SIZE];
  byte hexHeader[SHA256_SIZE];
  SHA256 hasherR, hasherD;

  //----------------------------------------------------------------- Print the address of the resource to the Serial port 
  Serial.print("Resource Address: ");
  Serial.println(resourceAddress);
  

  
  //  #########################################################
  //  # Prepare the packet for private resource registration. #
  //  #########################################################
  duration = 0;
  timeBegin = micros();

  //----------------------------------------------------------------- Generation of private tag that will be used during registration
  // Header = H ( private tag XOR private id of sender XOR private id of receiver )
  for(int i = 0; i < SHA256_SIZE; ++i)
    hexHeader[i] = privateTag[i] ^ privateID_s[i] ^ privateID_f[i];

  hasherR.doUpdate(hexHeader, SHA256_SIZE);
  hasherR.doFinal(privateTag_new);
  
  // Hash the attribute e.g. Type + VENDOR + ID
  // String att, att2, att3, tag1, tag2, tag3;

  //----------------------------------------------------------------- Encryption of the resource address
  int len = 0;
  bufferSize(resourceAddress, len);
  char encrypted[len];
  encrypt(resourceAddress, encrypted, len);
  
  
  //End of the operations
  timeEnd = micros();
  duration += timeEnd - timeBegin;
    

 //----------------------------------------------------------------- Print the results to the Serial port 
 Serial.print("Private Tag : ");
 for (byte i=0; i < SHA256_SIZE; i++)
  {
      if (privateTag_new[i]<0x10) { Serial.print('0'); }
      Serial.print(privateTag_new[i], HEX);
  }  
  Serial.println();
  Serial.print("Encrypted: ");
  Serial.println(encrypted); 
  Serial.print("Time: ");
  Serial.println(duration);

  
  //  #########################################################
  //  #  Prepare the packet for private resource Discovery.   #
  //  #########################################################
  duration = 0;
  timeBegin = micros();
  
  //----------------------------------------------------------------- Generation of private tag that will be used for discovery
  // Header = H ( private tag XOR private id of sender XOR private id of receiver )
  for(int i = 0; i < SHA256_SIZE; ++i)
    hexHeader[i] = privateTag[i] ^ privateID_s[i] ^ privateID_f[i];
  hasherD.doUpdate(hexHeader, SHA256_SIZE);
  hasherD.doFinal(privateTag_new);
  

  //----------------------------------------------------------------- Decryption of received encrypted resource address
  len = strlen(encrypted);
  char decrypted[len];
  //decrypt(encrypted, decrypted, len);  The function call has been replaced with the actual code here.
  len = len + 1; //re-adjust
  char decoded[len];
  decode_base64((unsigned char*)encrypted, (unsigned char*)decoded);
  bufferSize(encrypted, len);
  byte deciphered[len];
  AES aesDecryptor(key, iv, AES::AES_MODE_128, AES::CIPHER_DECRYPT);
  aesDecryptor.process((uint8_t*)decoded, deciphered, len);
  strcpy(decrypted, (char*)deciphered);
  
  //End of the operations
  timeEnd = micros();
  duration += timeEnd - timeBegin; 
  
  //----------------------------------------------------------------- Print the results to the Serial port 
  Serial.print("Private Tag : ");
  for (byte i=0; i < SHA256_SIZE; i++)
  {
      if (privateTag_new[i]<0x10) { Serial.print('0'); }
      Serial.print(privateTag_new[i], HEX);
  }  
  Serial.println();
  Serial.print("Decrypted: ");
  Serial.println(decrypted);
  Serial.print("Time: ");
  Serial.println(duration);

   // Update the private tag for next round
  for (byte i=0; i < SHA256_SIZE; i++)
      privateTag[i] = privateTag_new[i];

  delay(5000);
}
