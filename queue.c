#include <stdio.h>
#include <stdlib.h>
#include "queue.h"
//creates a queue and returns its pointer
struct queue *create_queue(void){ 
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

//destroys the queue and frees the memory to prevent memory leaks
void destroy_queue(struct queue *q){  
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}

// checks if queue is empty
int isempty(struct queue *q){ 
  return(q->head==NULL);
}

//enqueues a node with the required arguments for threads to call analyse()
void enqueue(struct queue *q, const unsigned char *item ,struct pcap_pkthdr *header ,int item1){ 
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item=item;
  new_node->header = header;
  new_node->item1 = item1;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}
//dequeues a the head node
void dequeue(struct queue *q){ 
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}


