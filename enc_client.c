#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

/**
* Client code
* 1. Create a socket and connect to the server specified in the command arugments.
* 2. Prompt the user for input and send that input as a message to the server.
* 3. Print the message received from the server and exit the program.
*/

// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
  exit(0); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portnumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portnumber);

  address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

int main(int argc, char *argv[]) {
  int socketFD, charsWritten, charsRead;
  struct sockaddr_in serverAddress;
  char buffer[256];
  char ack[10];
  
  // Check usage & args
  if (argc < 4) { 
    fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
    exit(0); 
  } 

  // Create a socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0){
    error("CLIENT: ERROR opening socket");
  }

   // Set up the server address struct
  setupAddressStruct(&serverAddress, atoi(argv[3]));

  printf("CLIENT: Attempting to connect to the server...\n");
  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
    error("CLIENT: ERROR connecting");
  }

  // Clear out the buffer array
  memset(buffer, '\0', sizeof(buffer));
  strncpy(buffer, "enc_client_key", sizeof(buffer) - 1);
  printf("CLIENT: Sending verification key: \"%s\"\n", buffer);

  // Send verification key to server
  // Write to the server
  charsWritten = send(socketFD, buffer, strlen(buffer), 0); 
  if (charsWritten < 0){
    error("CLIENT: ERROR writing to socket");
  }
  if (charsWritten < strlen(buffer)){
    printf("CLIENT: WARNING: Not all data written to socket!\n");
  }
  recv(socketFD, ack, sizeof(ack) - 1, 0);

  // Clear out the buffer array
  memset(buffer, '\0', sizeof(buffer));
  strncpy(buffer, argv[1], sizeof(buffer) - 1);

  // Send plaintext to server
  // Write to the server
  charsWritten = send(socketFD, buffer, strlen(buffer), 0); 
  if (charsWritten < 0){
    error("CLIENT: ERROR writing to socket");
  }
  if (charsWritten < strlen(buffer)){
    printf("CLIENT: WARNING: Not all data written to socket!\n");
  }

  recv(socketFD, ack, sizeof(ack) - 1, 0);

  memset(buffer, '\0', sizeof(buffer));
  strncpy(buffer, argv[2], sizeof(buffer) - 1);

  // Send key to server
  // Write to the server
  charsWritten = send(socketFD, buffer, strlen(buffer), 0); 
  if (charsWritten < 0){
    error("CLIENT: ERROR writing to socket");
  }
  if (charsWritten < strlen(buffer)){
    printf("CLIENT: WARNING: Not all data written to socket!\n");
  }

  recv(socketFD, ack, sizeof(ack) - 1, 0);

  // Get return message from server
  // Clear out the buffer again for reuse
  for (int i = 0; i < 2; i++) {
    memset(buffer, '\0', sizeof(buffer)); 
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (charsRead < 0) {
        error("CLIENT: ERROR reading from socket");
    }
    printf("CLIENT: I received this from the server: \"%s\"\n", buffer);
}

  // Close the socket
  close(socketFD); 
  return 0;
}
