// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define LOCAL_PORT 10000
#define PORT	 8080 
// #define PORT	 5000
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


	struct sockaddr_in	 servaddr, clientaddr; 

	// Creating socket file descriptor 
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	}

	memset(&clientaddr, 0, sizeof(struct sockaddr_in));
	clientaddr.sin_family = AF_INET;
    clientaddr.sin_addr.s_addr = INADDR_ANY;
    clientaddr.sin_port = htons(LOCAL_PORT);//UDP 广播包 本地端口
    socklen_t clientaddr_len = sizeof(struct sockaddr);
 
    if(bind(sockfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)))//绑定端口
    {
        printf("####L(%d) client bind port failed!\n", __LINE__);
        close(sockfd);//关闭socket
        exit(-1);
    }
 
	memset(&servaddr, 0, sizeof(servaddr)); 
	
	// Filling server information 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_port = htons(PORT); 
	servaddr.sin_addr.s_addr = inet_addr("10.11.1.1"); // inet_addr("10.11.1.1")  INADDR_ANY
	
	int n, len; 
	

    //  发送结构体
	// My_UDP udp_buf = {800, "Hello -🍉123-!--", "ggg🍆hhh", 1.11};
	// sendto(sockfd, (char*)&udp_buf, sizeof(udp_buf), 
	// MSG_CONFIRM, (const struct sockaddr *) &servaddr, 
	// sizeof(servaddr)); 


    //  发送字符串
	char *hello = "Test---"; 
	sendto(sockfd, (const char *)hello, strlen(hello), 
		MSG_CONFIRM, (const struct sockaddr *) &servaddr, 
			sizeof(servaddr)); 

	printf("Client message sent.\n"); 


	n = recvfrom(sockfd, (char *)buffer, MAXLINE, 
				MSG_WAITALL, (struct sockaddr *) &clientaddr, 
				&clientaddr_len); 
	
	buffer[n] = '\0'; 
	printf("Server : %s\n", buffer); 

	close(sockfd); 
	return 0; 
} 

