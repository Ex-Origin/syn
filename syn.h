#include<pthread.h>

/* The max thread number */
#define MAXCHILD 128


#define MODEL_FAST 0
#define MODEL_NORMAL 1
#define MODEL_SET_IP 2
#define MODEL_SET_PORT 3
#define MODEL_SET_IP_AND_PORT 4
#define MODEL_DEBUG 5


typedef struct  ip {
	unsigned char       hl;
	unsigned char       tos;
	unsigned short      total_len;
	unsigned short      id;
	unsigned short      frag_and_flags;
	unsigned char       ttl;
	unsigned char       proto;
	unsigned short      checksum;
	unsigned int        sourceIP;
	unsigned int        destIP;
}ip_struct;

typedef struct  tcphdr {
	unsigned short      sport;
	unsigned short      dport;
	unsigned int        seq;
	unsigned int        ack;
	unsigned char       lenres;
	unsigned char       flag;
	unsigned short      win;
	unsigned short      sum;
	unsigned short      urp;
}tcphdr_struct;

typedef struct  ip_and_tcp{
	ip_struct _ip;
	tcphdr_struct tcp;
}ip_tcp;

typedef union int_and_short{
	unsigned int sum;
	unsigned short low_and_high[2];
}int_short;


/* Edit the interrupt of Control + C */
void sig_int(int signo);

//It doesn't have to be calculated. The system will do it for us.
unsigned short ip_checksum(unsigned short *buffer);


void init_header(ip_struct *ip, tcphdr_struct *tcp,char *dst_ip,int dst_port);

//Convenient to pass parameters and manage
typedef struct thread_argument{
    int model;

    struct sockaddr_in *addr;
    char *dst_ip;
    char source_ip[0x20];
    int dst_port;
    int source_port;
    int sockfd;
    int time;
    pthread_mutex_t *mutex;
}thread_arg;

//for Thread start
void *send_synflood(void *arg);