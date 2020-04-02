#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "checksum.h"
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <osip2/osip.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/sdp_message.h>

char * new_contact = NULL;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int result = -1;

    int id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);    
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("HWPROT=0x%04x HOOK=%u ID=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);

        unsigned char *pkgdata;

        int len_pkgdata = nfq_get_payload(nfa, &pkgdata);
        if (len_pkgdata >= 0)
            printf("PLDLEN=%d ", len_pkgdata);
        else
            return result;

        //set protocol stack headers for queue package
        struct iphdr *ip4h = (struct iphdr *) pkgdata;
        struct udphdr *udph = (struct udphdr *) (pkgdata + (ip4h->ihl * 4));
        const char *udp_data = ((char*) udph) + sizeof(struct udphdr);

        if (udph->uh_ulen >= 0)
            printf("UDPLEN=%d ", ntohs(udph->uh_ulen));
        fputc('\n', stdout);

        osip_message_t *sip = NULL;
        osip_message_init(&sip);
        //get sip message from nfqueue package
        if(osip_message_parse(sip, udp_data, ntohs(udph->uh_ulen)) == 0) {
            osip_contact_t *header_contact =NULL;
            osip_body_t *header_body =NULL;
            osip_message_get_contact(sip, 0, &header_contact);
            osip_message_get_body(sip, 0, &header_body);
            if(header_contact || header_body) {
                //replace contact
                if(header_contact){
                    printf("replace contact %s ", header_contact->url->host);
                    free(header_contact->url->host);
                    header_contact->url->host = malloc(strlen(new_contact)+1);
                    strcpy(header_contact->url->host, new_contact);
                    printf("to %s\n", header_contact->url->host);
                }
                //replace body
                if(header_body){
                    sdp_message_t *sdp = NULL;
                    sdp_message_init(&sdp);
                    if(sdp_message_parse(sdp, header_body->body) == 0){

                        if(sdp_message_o_addr_get(sdp)){
                            printf("replace owner addr %s ", sdp_message_o_addr_get(sdp));
                            char *username = sdp_message_o_username_get(sdp);
                            char *sess_id = sdp_message_o_sess_id_get(sdp);
                            char *sess_version = sdp_message_o_sess_version_get(sdp);
                            char *nettype = sdp_message_o_nettype_get(sdp);
                            char *addrtype = sdp_message_o_addrtype_get(sdp);
                            sdp_message_o_origin_set(sdp, username, sess_id, sess_version, nettype, addrtype, new_contact);
                            printf("to %s\n", sdp_message_o_addr_get(sdp));
                        } else {
                            printf("cannot get sdp message owner addr\n");
                        }

                        if(sdp_message_c_addr_get(sdp, -1, -1)){
                            printf("replace connection addr %s ", sdp_message_c_addr_get(sdp, -1, -1));
                            //need remove old c in sdp
                            free(sdp->c_connection);
                            sdp->c_connection=NULL;
                            sdp_message_c_connection_add(sdp, 0, "IN", "IP4", new_contact, NULL, 0);
                            printf("to %s\n", sdp_message_c_addr_get(sdp, 0, 0));
                        } else {
                            printf("cannot get sdp message connection addr\n");
                        }

                        //remove old body
                        osip_free(header_body);
                        osip_list_remove(&sip->bodies, 0);
                        //set new body
                        char *body = NULL;
                        sdp_message_to_str(sdp, &body);
                        osip_message_set_body(sip, body, strlen(body));
                    } else {
                        printf("cannot get sdp message\n");
                    }
                    //TODO: Cause memory leak maybe, I don't know why the sdp can't be free.
//                    sdp_message_free(sdp);
//                    printf("debug mark\n");
                }

                //convert sip message with new contact to string
                osip_message_force_update(sip);
                char *new_sipdata=NULL;
                size_t length=0;
                osip_message_to_str(sip, &new_sipdata, &length);

                //malloc memory for new package
                size_t buf_size = (ip4h->ihl * 4) + sizeof(struct udphdr) + length;
                unsigned char *buf = malloc(buf_size);

                //set protocol stack headers for package buffer
                struct iphdr *buf_ip4h = (struct iphdr *) buf;
                struct udphdr *buf_udph = (struct udphdr *) (buf + (ip4h->ihl * 4));
                struct pseudo_iphdr *buf_pseudo_ip4h = (struct pseudo_iphdr *) (((char *)buf_udph) - sizeof(struct pseudo_iphdr));
                char *buf_udp_data = ((char*) buf_udph) + sizeof(struct udphdr);

                //put new SIP message into package buffer
                memcpy(buf_udp_data, new_sipdata, length);

                //copy udp header
                memcpy(buf_udph, udph, sizeof(struct udphdr));
                buf_udph->uh_ulen = htons(length + sizeof(struct udphdr));
                //udp checksum
                buf_udph->uh_sum = 0;
                buf_pseudo_ip4h->dest = ip4h->daddr;
                buf_pseudo_ip4h->source = ip4h->saddr;
                buf_pseudo_ip4h->zero = 0;
                buf_pseudo_ip4h->protocol = IPPROTO_UDP;
                buf_pseudo_ip4h->udp_length = buf_udph->uh_ulen;
                buf_udph->uh_sum = checksum((u_int16_t *)buf_pseudo_ip4h, sizeof(struct pseudo_iphdr) + ntohs(buf_udph->uh_ulen));

                //copy ip header
                memcpy(buf, pkgdata, (ip4h->ihl * 4));
                buf_ip4h->tot_len = htons(buf_size);
                buf_ip4h->check = 0;
                //ip checksum
                buf_ip4h->check = checksum((u_int16_t *)buf_ip4h, buf_ip4h->ihl*4);

                //send the package now
                result = nfq_set_verdict(qh, id, NF_ACCEPT, buf_size, buf);

                free(new_sipdata);
                free(buf);
            } else {
                printf("cannot get sip message contact\n");
                result = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }
        } else {
            printf("cannot parse sip message\n");
            result = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
        osip_message_free(sip);
    }

    return result;
}

int main(int argc, char *argv[])
{
    u_int16_t queue = 0;

    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "q:c:")) != -1)
        switch (c)
        {
        case 'q':
            queue = atoi(optarg);
            break;
        case 'c':
            new_contact = optarg;
            printf("new contact set to %s\n", new_contact);
            break;
        case '?':
            if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
            return 1;
        default:
            abort ();
        }

    printf("Initialise the oSIP parser\n");
    parser_init();

    printf("opening library handle\n");
    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    struct nfq_q_handle *qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("Waiting for packets...\n");

    int fd = nfq_fd(h);
    for (;;) {
        char buf[4096] __attribute__ ((aligned));
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);


    return 0;
}

