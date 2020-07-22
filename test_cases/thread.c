#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<assert.h>
#include<string.h>
#include<unistd.h>
struct node_list
{
    unsigned long key;
    char arr[256];
    struct node_list *next;
    /* data */
};

struct node_list *list_head = NULL;
struct node_list *list_tail = NULL;

unsigned long key_val = 0;
pthread_mutex_t ll_lock;



void* insert_node(void* arg){
    
    // unsigned long key_val =*((unsigned long*)key);
    // printf("%ld\n",key_val);

    while(1){

        pthread_mutex_lock(&ll_lock);
        struct node_list *node = (struct node_list*)malloc(sizeof(struct node_list));

        if(list_tail == NULL){
            node->key = 1;
        }else{
            node->key = list_tail->key + 1;
        }
        for(int i=0;i<26;i++){
            node->arr[i] = (char)i+'A';
        }
        node->arr[255]='\0';


        if(list_head == NULL){
            list_head = node;
            list_tail = node;
        }else{
            list_tail->next = node;
            list_tail = node;
        }
        pthread_mutex_unlock(&ll_lock);

        if(node->key >= key_val)break;
    }
}

void print_list(){
    struct node_list *tmp = list_head;

    unsigned long k = 1;
    while(tmp){
       // printf("%ld, ",tmp->key);
        assert( k == tmp->key);
        k++;
        tmp = tmp->next;
    }
}



int main(void){

    unsigned long nr_node, nr_dump;

    printf("Enter nr of linked list node to be inserted \n");
    scanf("%ld",&nr_node);

    printf("Enter nr of pre_dumps you want to take\n");
    scanf("%ld",&nr_dump);

    key_val = nr_node;

    int iter = nr_dump;

    for(int i=1; i<=iter; i++){

        key_val = (nr_node/nr_dump)*i;

        pthread_t t1,t2,t3,t4;
        pthread_create(&t1, NULL,insert_node, NULL);
        pthread_create(&t2, NULL,insert_node,NULL);
        pthread_create(&t3, NULL,insert_node,NULL);
        pthread_create(&t4, NULL,insert_node,NULL);

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        pthread_join(t3, NULL);
        pthread_join(t4, NULL);

        int get;
        printf("Insertion %ld for first pre-dump is done\n",key_val);
        printf("Process Id : %d Press key to continue\n",getpid());
        scanf("%d",&get);
    
    }


    print_list();
    printf("All Matched Completed !\n\n"); 

    return 0;
}