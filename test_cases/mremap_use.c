#define _GNU_SOURCE 
/*
 * This experiment is done to understand the behaviour of mmap and
 * mremap like can mremap split vma into two vma and its rezize usecase
 * 
 * Experiment :
 *      you have one filled vma     A|+++++++++++++++++++++++++++++++++++++++++++|B 10000
 * 
 *      you have three empty vma    B|--------|C   ----->  D|------------------|E   ---->   F|-------------|G
 *  
 *      we have to mremap some part from vma(A-B) into (B-C) (D-E) (F-G)
 *         
 * Copy            500                         1000                            700
 *             B|+++++----|C   ----->  D|----++++++++----|E   ---->   F|------+++++++|G
 * 
 * Actual Size  2000                        4000                        2000
 */


#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>



#define PAGE_SIZE 4096




void print_maps(){

	int fd_from,fd_to;
	char buf[4096];
	ssize_t nread;
	fd_from = open("/proc/self/maps",O_RDONLY);
	fd_to = open("maps_",O_WRONLY|O_CREAT|O_APPEND,0666);

	while(nread = read(fd_from,buf,sizeof(buf)),nread > 0){
		char *out_ptr;
		ssize_t nwritten;
		out_ptr = buf;

		do {
			nwritten = write(fd_to,out_ptr,nread);
			if(nwritten >= 0){
				nread -= nwritten;
				out_ptr += nwritten;
			}
		}while (nread >0);

	}
	close(fd_from);
	close(fd_to);
}

int main(void){

    unsigned long nr_pages, old_size,first_size,sec_size,third_size,copy_size,offset=0;

    //scanf("%ld",&nr_pages);

    nr_pages = 10000;

    old_size = nr_pages * PAGE_SIZE;
    void *filled_vma = mmap(NULL,old_size, PROT_NONE,MAP_PRIVATE | MAP_ANONYMOUS |MAP_POPULATE, 0, 0);

    printf("First Mmap Address %p\n\n",filled_vma);

    first_size = 2000 *PAGE_SIZE;
    sec_size   = 4000 *PAGE_SIZE;
    third_size = 2000 *PAGE_SIZE;


    //creating three empty vma

    void *first_addr    = mmap(NULL,first_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
    printf("first_addr Mmap Address %p\n\n",first_addr);


    void *sec_addr      = mmap(NULL,sec_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
    printf("sec_addr Mmap Address %p\n\n",sec_addr);

    void *third_addr    = mmap(NULL,third_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
    printf("third_addr Mmap Address %p\n\n",third_addr);


    /*
     * Printing self maps
     *  
     */

    
    


    copy_size = 500*PAGE_SIZE;
    void *tgt_addr = mremap((void *)((unsigned long)filled_vma + offset),copy_size,copy_size,MREMAP_FIXED|MREMAP_MAYMOVE,first_addr);
    printf("mremap addr %p :    tgt_adrr %p\n",tgt_addr,first_addr);

    offset += copy_size;
    copy_size = 2000*PAGE_SIZE;

    tgt_addr = mremap((void *)((unsigned long)filled_vma + offset),copy_size,copy_size,MREMAP_FIXED|MREMAP_MAYMOVE,sec_addr);
    printf("mremap addr %p :    tgt_adrr %p\n",tgt_addr,sec_addr);
    
    offset += copy_size;
    copy_size = 1000*PAGE_SIZE;
    tgt_addr = mremap((void *)((unsigned long)filled_vma + offset),copy_size,copy_size,MREMAP_FIXED|MREMAP_MAYMOVE,third_addr);
    printf("mremap addr %p :    tgt_adrr %p\n",tgt_addr,third_addr);



    return 0;
}