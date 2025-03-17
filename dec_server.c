#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

char *processFile(char* cipherTextPath, char* keyFilePath){
  size_t len_ciphertext = 0;
  size_t len_key = 0;
  char *ciphertextString = NULL;
  char *keyFileString = NULL;
  int textLetter;
  int keyLetter;

  printf("Starting processing files\n");

  FILE *messageFile = fopen(cipherTextPath, "r");
  FILE *keyFile = fopen(keyFilePath, "r");

  if (!messageFile || !keyFile) {
    printf("Error opening files.\n");
    return NULL;
  }

  if (getline(&ciphertextString, &len_ciphertext, messageFile) == -1){
    printf("Error reading ciphertext file.\n");
    return NULL;
  }

  if (getline(&keyFileString, &len_key, keyFile) == -1){
    printf("Error reading key file.\n");
    return NULL;
  }
  
  len_ciphertext = strlen(ciphertextString);
  len_key = strlen(keyFileString);
  
  fclose(messageFile);
  fclose(keyFile);

  if (len_key < len_ciphertext){
    free(ciphertextString);
    free(keyFileString);
    return NULL;
  }

  char *plainText = malloc(len_ciphertext + 1);
  int plainLetter;

  for (int i = 0; i< len_ciphertext - 1; i++){
    if (ciphertextString[i] == ' '){
      textLetter = 26;
    }else{
      textLetter = ciphertextString[i] - 'A';
    }

    if (keyFileString[i] == ' '){
      keyLetter = 26;
    }else{
      keyLetter = keyFileString[i] - 'A';
    }

    plainLetter = (textLetter - keyLetter) % 27;
    if (plainLetter == 26){
      plainText[i] = ' ';
    }else{
      plainText[i] = 'A' + plainLetter;
    }
  }

  plainText[len_ciphertext] = '\0';

  free(ciphertextString);
  free(keyFileString);
  printf("%s\n", plainText);
  return plainText;

}


// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

int main(int argc, char *argv[]){
  int connectionSocket, charsReadCipherText, charsReadKey,verifyKeyRead;
  char ciphertext[256];
  char key[256];
  char verifykey[50];
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);


  // Check usage & args
  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 
  
  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }

  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5); 
  
  // Accept a connection, blocking if one is not available until one connects
  while(1){
    // Accept the connection request which creates a connection socket
    connectionSocket = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (connectionSocket < 0){
      error("ERROR on accept");
    }

    printf("SERVER: Connected to client running at host %d port %d\n", 
                          ntohs(clientAddress.sin_addr.s_addr),
                          ntohs(clientAddress.sin_port));

    // Get the message from the client and display it
    memset(ciphertext, '\0', 256);
    memset(key, '\0', 256);
    memset(verifykey, '\0', 50);

    verifyKeyRead = recv(connectionSocket, verifykey, 49, 0);
    if (verifyKeyRead < 0) {
      error("ERROR reading verification key from socket");
    }

    verifykey[verifyKeyRead] = '\0';
    verifykey[strcspn(verifykey, "\n")] = '\0';

    if (strcmp(verifykey, "dec_client_key") != 0){
      printf("SERVER: Verification key mismatch! Closing connection.\n");
      close(connectionSocket);
      continue;
    }

    send(connectionSocket, "ACK", 3, 0);

    // Read the client's message from the socket
    charsReadCipherText = recv(connectionSocket, ciphertext, 255, 0);
    send(connectionSocket, "ACK", 3, 0);
    if (charsReadCipherText < 0){
      error("ERROR reading ciphertext from socket");
    }

    charsReadKey = recv(connectionSocket, key, 255, 0);
    send(connectionSocket, "ACK", 3, 0);
    if (charsReadKey < 0){
      error("ERROR reading key from socket");
    }

    //From here on, the plaintext file name from the client is stored in plaintext and they key file name
    //from the cleint is stored in key
    //Need to: open the files, verify that the key is at least as big as the plaintext,
    //write back the cipher text to enc_client on the connectionsocket
    
    char *cipherText = processFile(cipherText, key);
    if (cipherText == NULL){
      printf("Error: Cipher text is NULL\n");
    }else if(cipherText[0] == '\0'){
      printf("Cipher text is empty!\n");
    }else{
      printf("Server printing cipher text: %s\n", cipherText);
    }
    if(cipherText == NULL){
      printf("SERVER ERROR: Key is shorter than ciphertext\n");
      close(connectionSocket);
      continue;
    }else{
      send(connectionSocket, cipherText, strlen(cipherText), 0);
    }

    // Close the connection socket for this client
    close(connectionSocket); 
  }
  // Close the listening socket
  close(listenSocket); 
  return 0;
}

