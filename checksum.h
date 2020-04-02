#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdlib.h>
#include <sys/types.h>

struct pseudo_iphdr
{
        u_int32_t source;
        u_int32_t dest;
        u_int8_t zero; //reserved, check http://www.rhyshaden.com/udp.htm
        u_int8_t protocol;
        u_int16_t udp_length;
};

u_int16_t checksum(u_int16_t *addr, int len) {
    //Prepare for different architectures
    static u_int16_t test[] = { 0x1234 };
    int enable_addzero = ((u_int32_t) ((u_int16_t) (*(u_int8_t *) test) << 8)) == 0x00001200;        // need add 0
    //checksum
    u_int32_t sum = 0;
    while (len > 1)
    {
            sum += *addr++;
            len -= 2;
    }
    if (len == 1)
    {
            //Prepare for different architectures
            if (enable_addzero)
            {
                    u_int8_t tmp = *(u_int8_t *) addr;
                    u_int16_t last = (u_int16_t) (tmp << 8);        // add 0
                    sum += last;
            }
            else
                    sum += *(u_int8_t*) addr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);  //add carry
    return ~sum;
}

#endif // CHECKSUM_H
