#include "sniff.h"
#include "analysis.h"
#include "arraylist.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "dispatch.h"
#include "queue.h"
#include "global_vars.h"

//queue where the main server thread adds work and from where the worker threads pull work
struct queue *work_queue;
//array where the worker threads will store unique ip addresses of syn flooding packets
struct array *syn_addr;
//global structure that stores the number of malicious packets ( a required ouput )
struct global_vars malicious;
//mutex lock required for the shared queue
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
//condition variable to wake threads up to prevent wastage of cpu resources
pthread_cond_t no_packets   = PTHREAD_COND_INITIALIZER;

pcap_t *pcap_handle;
//exit flag for the signal handler
static int signalfired = 0;

// signal handler function
void handle_sigint(int sig) {
  signalfired = 1;

  //breaks the loop of pcap_loop
  pcap_breakloop(pcap_handle);
}

//callback function
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  int* verbose = (int *)args;
  struct pcap_pkthdr header1 = *header;
  if (packet == NULL) {
    printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      
  }else {
    //If verbose is set to 1, dump raw packet to terminal
      if (*verbose) {
        dump(packet, header->len);
      }
      // Dispatch packet for processing
      dispatch(&header1, packet, *verbose);
      // broadcast to threads to pull work from the work queue and perform analyse 
      pthread_cond_broadcast(&no_packets);    
  }
}
// function to be executed by each worker thread
void*handle_conn(void* arg) {
  while(1){
  
    pthread_mutex_lock(&queue_mutex);
    //puts thread to sleep when work queue is empty 
    while(isempty(work_queue)) {
      pthread_cond_wait(&no_packets,&queue_mutex);
    }
    //pulls information out of work queue
    const unsigned char *packet = work_queue -> head -> item;
    struct pcap_pkthdr *header = work_queue -> head -> header;
    int my_verbose = work_queue -> head -> item1;
    dequeue(work_queue);
    pthread_mutex_unlock(&queue_mutex);
    analyse(header,packet,my_verbose);
  }
  pthread_exit(NULL);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
                                                                                                                                                                                                                                                                                                                                                                                                     
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().
  // Number of threads used is cpu cores + 1;
  pthread_t threads[7];
  int i;
  //creates the work queue
  work_queue = create_queue();
  //creates the dynamic array
  syn_addr = initArray(5);
  //signal handler function
  signal(SIGINT, handle_sigint);

  //create the worker threads
  for (i = 0; i < 7; i++) {
    pthread_create(&threads[i], NULL, handle_conn, NULL);
  }
  //sniffs for packets in a loop, argument set to -1 so that it loops continously
  pcap_loop(pcap_handle, -1, got_packet, (u_char *)&verbose);

  //true when Ctrl C is pressed
  if(signalfired) {
    printf("\n");
    printf("Intrusion Detection Report :\n");
    printf("%d SYN packets deteted from %d different IPs (syn attack)\n",malicious.num_syn_packets,syn_addr->used);
    printf("%d ARP responses (cache poisoning)\n", malicious.num_arp_packets);
    printf("%d URL Blacklist violations (%d google and %d facebook)\n", malicious.num_facebook+malicious.num_google,malicious.num_google,malicious.num_facebook);
    //frees dynamically allocated memory to prevent memory leaks
    freeArray(syn_addr);
    destroy_queue(work_queue);
    //exits the program
    exit(0);

  }
}


// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
