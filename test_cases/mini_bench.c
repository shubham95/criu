#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/fcntl.h>
#include<signal.h>
#include<sys/ioctl.h>
#include<sys/mman.h>
#include<sys/unistd.h>

#define MB_SIZE 1048576

int main(void){
    
    unsigned long rate,size,written_size=0;
    printf("Enter memory allocation rate : Ex 1mb/s, 2mb/s, 4mb/s ....\n");
    scanf("%ld",&rate);

    rate *= MB_SIZE;
    size = rate/10;

    int i =0;
    int interval = 10;
    int out_flag = 0;
    int one_time = 1;
    while(1){

        interval = 10;
        while(interval--){
            
            void *addr = malloc(size);
            memset(addr,0,size);

            written_size+=size;
            printf("PID: %d i : %d MB written : %ld\n",getpid(),i++,written_size/MB_SIZE);

            if(one_time && written_size >= 512*MB_SIZE){
                printf("Please start taking your dump\n");
                int t;
                scanf("%d",&t);
                one_time = 0;
            }
            if(written_size >= 1024*MB_SIZE){
                out_flag=1;
                break;
            }
            usleep(100000);
        }
        if(out_flag==1){
            break;
        }

    }
}