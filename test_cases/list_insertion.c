#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<assert.h>

struct node_list
{
    uint64_t key;
    char arr[256];
    struct node_list *next;
    /* data */
};

struct node_list *list_head = NULL;
struct node_list *list_tail = NULL;


void insert_node(uint64_t key){
    struct node_list *node = (struct node_list*)malloc(sizeof(struct node_list));
    node->key =key;

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
}


void print_list(){
    struct node_list *tmp = list_head;

    uint64_t i=1;
    while(tmp){
        //printf("key %ld, val %s \n",tmp->key,tmp->arr);
        
        assert( i == tmp->key);

        // for(int i=0; i<256; i++){
        //     printf(" %c",tmp->arr[i]);
        // }
        // printf("\n");
        i++;

        tmp = tmp->next;
    }
}



int main(void){

    uint64_t nr_nodes=0,t;
    printf("Enter Nr of list you want to insert..\n");
    scanf("%ld",&nr_nodes);

    for(uint64_t i =1; i<=nr_nodes; i++){
        insert_node(i);
    }

    printf("Insertion completed  please take dump\n");
    scanf("%ld",&t);



    /*
     * Use assert to check whether all entries are correct or not
     */

    print_list();

    printf("All matched!\n\n");

    

    return 0;
}