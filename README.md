# SIP Message Modifier

## Overview
This program intercepts and modifies SIP (Session Initiation Protocol) messages passing through a Linux Netfilter queue. It's specifically designed to update the Contact header and SDP (Session Description Protocol) body to reflect changes such as new IP addresses or hostnames. This is typically useful for scenarios involving NAT (Network Address Translation), load balancing, or network topology changes.

## Dependencies
- libnetfilter_queue
- libosip2

Ensure these libraries are installed and available in your system to compile and run the program.

## Compilation
To compile the program, you will need to link against the necessary libraries. Here is a sample gcc command:

`gcc -o sip_modifier main.c -lnetfilter_queue -losip2`


## Usage
The program requires root privileges due to the nature of network packet manipulation.

`sudo ./sip_modifier -q <queue_num> -c <new_contact_ip>`


### Options
- `-q <queue_num>`: Specify the NFQUEUE number to which the program will bind and listen.
- `-c <new_contact_ip>`: Define the new contact IP address that will replace the original in the SIP and SDP messages.

## How It Works
- The program binds to a specified NFQUEUE.
- It parses each packet to determine if it contains a SIP message.
- If a SIP message is found, it modifies the Contact header and the SDP body to incorporate the new contact IP address specified.
- The modified packet is then re-injected back into the network stack for normal processing.

## Important Notes
- Running this program can affect your network's SIP traffic. Ensure it is used in a controlled environment.
- The program handles basic error checking, but extensive testing is recommended for production environments.
