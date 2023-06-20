
// data structure for each node
struct node{ 
  const unsigned char * item;
  struct pcap_pkthdr *header;
  int item1;
  struct node *next;
};

typedef struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
} Queue;

struct queue *create_queue(void);

int isempty(struct queue *q);

void enqueue(struct queue *q, const unsigned char * item,struct pcap_pkthdr *header, int item1);

void dequeue(struct queue *q);

void printqueue(struct queue *q);

void destroy_queue(struct queue *q);

//work queue where threads will pull work from(declared here so that it can be shared across c files)
extern Queue *work_queue;