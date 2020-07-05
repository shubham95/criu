#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<assert.h>
#include<unistd.h>

struct node_list
{
    uint64_t start,end;
    struct node_list *next;
    /* data */
};

struct node_list *list_head = NULL;
struct node_list *list_tail = NULL;


void insert_node(uint64_t key){
    struct node_list *node = (struct node_list*)malloc(sizeof(struct node_list));
    node->start = key;
    node->end   = key+1;


    if(list_head == NULL){
        list_head = node;
        list_tail = node;
    }else{
        list_tail->next = node;
        list_tail = node;
    }
}


int merge_list(){
    
    struct node_list *A = list_head;
    struct node_list *B = A->next;


    if(A==NULL || B==NULL){
        return 0;
    }


    while(A&&B){

        if(A->end == B->start){
            A->end = B->end;
            A->next = B->next;
            free(B);
            return 1;
        }else{
            A = B;
            B = B->next;
        }

    }
    
    
    return 0;


}

void print_list(){
    struct node_list *tmp = list_head;

    uint64_t i=1;
    while(tmp){
        printf(" start %ld  : end %ld \n",tmp->start,tmp->end);

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

    for(int i =0; i<nr_nodes;i++){
        merge_list();
        print_list();
    }

    //print_list();

    //printf("All matched!\n\n");

    

    return 0;
}