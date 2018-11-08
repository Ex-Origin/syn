#include<stdio.h>
#include <unistd.h>
#include<pthread.h>

pthread_mutex_t mutex = {0};

void f(void *v)
{
    
    int x=0;
    while(1)
    {
        pthread_mutex_lock( &mutex);
        pthread_mutex_unlock(&mutex);
        pid_t t=getpid();
        printf("%d\n",t);
        x++;
    }
}

int main(int argc, char const *argv[])
{
    puts("\
Usage: syn [OPTION] -a [destination_ip:destination_port]\n\
  -a [destination_ip:destination_port]  The target you need to attack.\n\
  -i [source_ip]                        Set the source ip.\n\
                                          Default random IP.\n\
  -p [source_port]                      Set the source port.\n\
                                          Default random port.\n\
  -t [millisecond]                      Delay after each attack.\n\
                                          Default 0.\n\
  -f                                    Open fast model, it need\n\
                                          -i and -p argument.\n\
");
    pthread_t t;
    pthread_create(&t, NULL, f, NULL);
    int in;
    while (1)
    {
        scanf("%d",&in);
        if(in==0)
        {
            pthread_mutex_lock( &mutex);
            puts("stop");
        }
        else if(in==1)
        {
            pthread_mutex_unlock(&mutex);
            puts("start");
        }
    }
    return 0;
}


