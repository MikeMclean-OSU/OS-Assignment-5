#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void processFile(char* filePath, char **readString){
  char *currLine = NULL;
  size_t len = 0;

  FILE *encFile = fopen(filePath, "r");

  if(getline(&currLine, &len, encFile) != -1){
    *readString = malloc(len);
    strncpy(*readString, currLine, len);
  }

  free(currLine);
  fclose(encFile);

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
  int connectionSocket, charsReadPlaintext, charsReadKey,verifyKeyRead;
  char plaintext[256];
  char key[256];
  char verifykey[50];
  char *plainTextFile = NULL;
  char *keyFile = NULL;
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
    printf("Server Getting Message\n");
    memset(plaintext, '\0', 256);
    memset(key, '\0', 256);
    memset(verifykey, '\0', 50);

    printf("Server Receiving Verification Key\n");
    verifyKeyRead = recv(connectionSocket, verifykey, 49, 0);
    printf("SERVER: Received verification key: \"%s\"\n", verifykey);
    if (verifyKeyRead < 0) {
      error("ERROR reading verification key from socket");
    }

    verifykey[verifyKeyRead] = '\0';
    verifykey[strcspn(verifykey, "\n")] = '\0';

    printf("Server Comparing Verification Key\n");
    if (strcmp(verifykey, "enc_client_key") != 0){
      printf("SERVER: Verification key mismatch! Closing connection.\n");
      close(connectionSocket);
      continue;
    }

    printf("Server Reading Plaintext\n");
    // Read the client's message from the socket
    charsReadPlaintext = recv(connectionSocket, plaintext, 255, 0);
    if (charsReadPlaintext < 0){
      error("ERROR reading plaintext from socket");
    }

    printf("Server Reading Key\n");
    charsReadKey = recv(connectionSocket, key, 255, 0);
    if (charsReadKey < 0){
      error("ERROR reading key from socket");
    }

    printf("SERVER: plaintext received this from the client: \"%s\"\n", plaintext);
    printf("SERVER: Received key: \"%s\"\n", key);

    // Send a Success message back to the client
    charsReadPlaintext = send(connectionSocket, 
                    "I am the server, and I received the plaintext message", 53, 0); 
    if (charsReadPlaintext < 0){
      error("ERROR writing to socket");
    }

    charsReadKey = send(connectionSocket, 
      "I am the server, and I received the key message", 47, 0); 
    if (charsReadKey < 0){
    error("ERROR writing to socket");
    }

    // Close the connection socket for this client
    close(connectionSocket); 
  }
  // Close the listening socket
  close(listenSocket); 
  return 0;
}
