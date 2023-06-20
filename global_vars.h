//a global structure that stores the number of malicious packets (can be shared between c files by including the header file)
typedef struct global_vars {
    int num_syn_packets;
    int num_arp_packets;
    int num_facebook;
    int num_google;
} global_vars;

extern global_vars malicious; 