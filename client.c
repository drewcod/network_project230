#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <netdb.h>

// read: cmd = r (read, receive)
// write: cmd = w or s (write, send)
// message is the buffer for read, for write it is the message being sent 
// length = -1 for maximum length; otherwise length is the cutoff for the message being written or read
int communicate(char cmd, char* message, int fd, int length) {
    int returned_val = -1;
    if (cmd == 'r') { // read
        if (length == -1) {
            returned_val = recv(fd, message, 2048, 0);
        } else {
            returned_val = recv(fd, message, length, 0);
        }
        if (returned_val < 0) {
            printf("Read message error\n");
            return -1;
        } else if (returned_val == 0) {
            printf("Nothing read\n");
        }
        message[returned_val] = '\0';
    } else if (cmd == 'w' || cmd == 's') { // write
        if (length == -1) {
            returned_val = send(fd, message, strlen(message), 0);
            if (returned_val > strlen(message) || returned_val < 0) {
                printf("Send message error\n");
                return -1;
            }
        } else {
            returned_val = send(fd, message, length, 0);
            if (returned_val > length || returned_val < 0) {
                printf("Send message error\n");
                return -1;
            }
        }
    } else {
        printf("Undefined behavior in communicate\n");
    }

    return returned_val;
}

int open_client_fd(int port, char* addr) {
    int client_fd;
    struct hostent *hp;
    struct sockaddr_in serveraddr;
    struct in_addr naddr;

    printf("Creating socket\n");

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        printf("client socket creation error\n");
        return -1;
    }

    if (inet_aton(addr, &naddr) == 0) {
        printf("inet_aton error\n");
        return -1;
    }

    hp = gethostbyaddr(&naddr, sizeof(naddr), AF_INET);
    if (hp == NULL) {
        printf("Error obtaining host by address from DNS\n");
        return -1;
    }

    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr = naddr;

    printf("Client is trying to connect to: hostname = %s; address = %s\n", hp->h_name, addr);

    if (connect(client_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        printf("error opening connect\n");
        return -1;
    }

    printf("Connection successful\n");
    return client_fd;
}

// returns alphabet and encrypted message in an array
void clean_message(char* message, char* alphabet, char* cleaned) {
    int numspaces = 0;
    int last_ind = 0;

    for (int i = 0; i < strlen(message); i++) {
        if (message[i] == ' ') {
            numspaces++;
            if (numspaces == 2) {
                last_ind = i + 1;
            } else if (numspaces == 3) {
                strncpy(alphabet, message + last_ind, i - last_ind);
                alphabet[i - last_ind] = '\0';
                last_ind = i + 1;
            }
        } else if (message[i] == '\n') {
            strncpy(cleaned, message + last_ind, i - last_ind);
            cleaned[i - last_ind] = '\0';
        }
    }
}

void decypher(char* formatted, char* message) {
    printf("Cleaning message...\n");
    char alphabet[256];
    char cleaned[2048];
    char decoded[2048];

    clean_message(message, alphabet, cleaned);
    // printf("Cleaned message = %s, %s\n", alphabet, cleaned);

    int i;
    for (i = 0; i < strlen(cleaned); i++) {
        decoded[i] = alphabet[(int)(cleaned[i]) - 97];
    }
    decoded[i] = '\0';
    
    strcpy(formatted, "cs230 ");
    strcat(formatted, decoded);
    strcat(formatted, "\n");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <username> <port> <host>\n", argv[0]);
        exit(0);
    }

    char* username = argv[1];
    int port = atoi(argv[2]);
    char* addr = argv[3];
    int client_fd = open_client_fd(port, addr);

    char hello[100] = "cs230 HELLO ";
    strcat(hello, username);
    strcat(hello, "\n");

    printf("Sending hello message: %s\n", hello);
    communicate('s', hello, client_fd, -1);
    printf("First message send successful\n");

    printf("Reading first response\n");
    char first_encr[2048];
    int length = communicate('r', first_encr, client_fd, sizeof(first_encr));
    printf("First encryption message: %s\n", first_encr);

    printf("Decyphering first message\n");
    char first_decy[2048];
    decypher(first_decy, first_encr);
    // printf("First message decyphered: %s\n", first_decy);

    // char test[] = "cs230 STATUS abcdefghijklmnopqrstxyzuvw zzyyxx\n";
    // char testDec[2048];
    // decypher(testDec, test);
    // printf("Test: %s\n", testDec);

    printf("Sending back first decypher\n");
    printf("Sent: %s\n", first_decy);
    communicate('s', first_decy, client_fd, -1);

    char mess[2048] = "";
    char substring[2048] = "";
    while(1) {
        communicate('r', mess, client_fd, sizeof(mess));
        if (strcmp(strncpy(substring, mess + (strlen(mess) - 4), 4), "BYE\n") == 0) {
            break;
        }
        printf("Server: %s\n", mess);
        char decoded[2048];
        decypher(decoded, mess);
        communicate('s', decoded, client_fd, -1);
        printf("Client: %s\n", decoded);
        mess[0] = '\0';
    }

    int i;
    while (mess[i] != '\n') {
        i++;
    }
    char key[2048];
    strncpy(key, mess + 6, i);
    printf("Hash key is: %s\n", key);

    if(close(client_fd) < 0) {
        printf("Error closing socket\n");
        return -1;
    }
    return 0;
}
// awmarceau@umass.edu 27993 128.119.243.147