# Operating-Systems-and-Computer-Networks
For this coursework you will implement a basic intrusion detection system. This will test your understanding of TCP/IP protocols (networks) and threading (OS) as well as your ability to develop a non-trivial program in C. The coursework contributes 20% of the total marks towards the module.

You have been provided with an application skeleton that is able to intercept (sniff) incoming packets and print them to the screen. The code uses the libpcap library to receive packets and strips the outer-most layer of the protocol stack. The goal of this coursework is to extend the skeleton to detect potentially malicious traffic in high-throughput networks. The key deliverables of this coursework and their associated weightings are as follows.

Extend the skeleton to efficiently intercept and correctly parse the IP and TCP protocol layers. (~30%)
Identify suspicious packets. Produce a report containing a breakdown of the malicious activity detected to be printed when the program exits. (~20%)
Implement a threading strategy to allow your code to deal with high packet throughput. (~20%)
Write a report no more than 2 pages in length (excluding references) explaining the design, implementation and testing of your solution. (~20%)
The final ~10% is awarded for code quality and adherence to relevant software engineering principles.
You must base your solution on the skeleton provided and it must be written entirely in the C programming language. You should only consider IPV4 - there are no additional marks available for IPV6 functionality. You may choose to use appropriate academic or industrial literature, which should be referenced appropriately. When writing an academic report, you should not write in first person (i.e., Don't write "I did this, I did that, etc.").

Code Skeleton
The coursework skeleton consists of several files, each with a specific purpose:

Makefile -
As this project spans multiple files we have provided a makefile to automate the build process for you. To compile your solution you should change into the src directory and then run the make command. This will build the application binary "../build/idsniff". Your solution should not require changes to this file.

main.c -
This file hosts the application entry point. It also contains logic to parse command line arguments, allowing you to set the verbose flag and specify the network interface to sniff. Your solution should not require changes to this file.

sniff.c -
This file contains the sniff function which captures packets from the network interface and passes them to your logic. A utility method called dump is also provided to output the raw packet data when debug mode is enabled. You should study this function carefully as it demonstrates how to parse a packet's ethernet header.

analysis.c -
This file is where you should put code to analyse packets and identify threats. Your logic should be called from the analyse method which runs each time a packet is intercepted.

dispatch.c -
This file is where you should put code to parallelise your system. At the moment, the dispatch method simply calls the analyse method in analysis.c . This sequential, single-threaded behaviour should be replaced by code to distribute work over multiple threads.
