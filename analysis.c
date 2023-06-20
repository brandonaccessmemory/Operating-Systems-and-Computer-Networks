#include "analysis.h"
#include "arraylist.h"
#include "global_vars.h"
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//mutex lock for the threads to access the global struct while avoiding any race conditions
pthread_mutex_t queue_mutex1 = PTHREAD_MUTEX_INITIALIZER;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  //cast the packet to a ether_header struct            
  struct ether_header *eth_header = (struct ether_header *) packet;

  // Decode Packet Data (Skipping over the ethernet header)
  const unsigned char *eth_payload = packet + ETH_HLEN;

  //Check for SYN FLOODING or BLACKLIST
  if( ntohs(eth_header->ether_type) == ETHERTYPE_IP ) {

    //Decode IP Header 
    struct ip *ip_header = (struct ip*) eth_payload;
    //Decode TCP header
    const struct tcphdr *tcp_header = (struct tcphdr*)(eth_payload + (ip_header->ip_hl)*4); 

    //checks if the ip protocol is tcp
    if (ip_header->ip_p == IPPROTO_TCP) {
      //Check for SYN FLOODING where syn == 1 and ack == 0 (no acknowledgement sent back)
      if (tcp_header->ack == 0 && tcp_header->syn == 1 &&
          tcp_header->urg == 0 && tcp_header->psh == 0 &&
          tcp_header->rst == 0 && tcp_header->fin == 0) {
        //locks the global variables to prevent race conditions    
        pthread_mutex_lock(&queue_mutex1);
        insertArray(syn_addr,ip_header->ip_src.s_addr);
        malicious.num_syn_packets++;
        pthread_mutex_unlock(&queue_mutex1);
      }

      //Check for Blacklist, 80 is the number of the http port
      if (ntohs(tcp_header->th_dport) == 80 ) {
        char *google   = "Host: www.google.co.uk";
        char *facebook = "Host: www.facebook.com";

        //gets to the payload to perform comparison with the message
        const char *tcp_payload = (const char *)(packet + ETH_HLEN + (ip_header->ip_hl)*4 + (tcp_header->th_off)*4);
        //check for occurence of google
        if(strstr(tcp_payload,google)) {
          //locks variable
          pthread_mutex_lock(&queue_mutex1);
          malicious.num_google++;
          pthread_mutex_unlock(&queue_mutex1);
          //prints source and destination ip address
          printf("=====================\n");
          printf("Source IP Address %s\n",inet_ntoa(ip_header->ip_src));
          printf("Destination IP address: %s\n",inet_ntoa(ip_header->ip_dst));
          printf("=====================\n");
        }

        //check for occurence of facebook
        if(strstr(tcp_payload,facebook)) {
          //locks variable
          pthread_mutex_lock(&queue_mutex1);
          malicious.num_facebook++;
          pthread_mutex_unlock(&queue_mutex1);
          //prints source and destination ip address
          printf("=====================\n");
          printf("Source IP Address %s\n",inet_ntoa(ip_header->ip_src));
          printf("Destination IP address: %s\n",inet_ntoa(ip_header->ip_dst));
          printf("=====================\n");
        }
      }
    }
  }

  //Check for ARP POISONING
  if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    struct arphdr *arp_header = (struct arphdr*)(eth_payload);
    //checks if it an arp response packet
    if(ntohs(arp_header->ar_op) == ARPOP_REPLY) {
      //locks variable
      pthread_mutex_lock(&queue_mutex1);
      malicious.num_arp_packets++;
      pthread_mutex_unlock(&queue_mutex1);
    }
  }
}
