#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"
#include "queue.h"


void dispatch( struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  //enqueue packets to work queue here essentially dispatching work to the worker threads
  enqueue(work_queue, packet,header,verbose);
}


