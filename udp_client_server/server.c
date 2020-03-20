// Server side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT	 8080 
#define MAXLINE 1024 

typedef struct
{
    unsigned int num;
    char msg[50];
    char msg2[50];
    double socre;
} My_UDP;

// Driver code 
int main() { 
	int sockfd; 
	char buffer[MAXLINE]; 
	char *hello = "Hello from server"; 
	struct sockaddr_in servaddr, cliaddr; 
	
	// Creating socket file descriptor 
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	} 
	
	memset(&servaddr, 0, sizeof(servaddr)); 
	memset(&cliaddr, 0, sizeof(cliaddr)); 
	
	// Filling server information 
	servaddr.sin_family = AF_INET; // IPv4 
	servaddr.sin_addr.s_addr = INADDR_ANY; // inet_addr("10.11.1.1");  // INADDR_ANY; // inet_addr("10.11.1.1"); // INADDR_ANY; // inet_addr("10.0.2.15"); // INADDR_ANY; 
	servaddr.sin_port = htons(PORT); 
	
	// Bind the socket with the server address 
	if (bind(sockfd, (const struct sockaddr *)&servaddr, 
			sizeof(servaddr)) < 0 ) 
	{ 
		perror("bind failed"); 
		exit(EXIT_FAILURE); 
	} 
	
	int len, bytes_read, servaddr_len;

	len = sizeof(cliaddr); //len is value/resuslt 

	servaddr_len = sizeof(servaddr);

    //  接收字符串
	bytes_read = recvfrom(sockfd, (char *)buffer, MAXLINE, 
				MSG_WAITALL, ( struct sockaddr *) &cliaddr, 
				&len); 
	buffer[bytes_read] = '\0'; 
	printf("Client : %s\n", buffer); 


    //  接收结构体
    // My_UDP h1;
    // memset(&h1, 0, sizeof(My_UDP));
    // bytes_read = recvfrom(sockfd, &h1, sizeof(My_UDP), MSG_WAITALL,
    //                           (struct sockaddr *)&cliaddr, &len);
    // printf("\n/**********************/");
    // printf("\nmsg: %s", h1.msg);
    // printf("\nmsg2: %s", h1.msg2);
    // printf("\nnum: %d", (h1.num));
    // printf("\nnum: %f\n", (h1.socre));
    // printf("/**********************/\n\n");

	sendto(sockfd, (const char *)hello, strlen(hello), 
		MSG_CONFIRM, (const struct sockaddr *) &cliaddr, 
			len); 
	printf("Reply message sent.\n"); 
	
	return 0; 
} 

