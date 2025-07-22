/*
 * SHELL FOR HOMEWORK 1, CS472
 *
 * Instructions are on class blackboard site
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
//#include <arpa/inet.h>

#include "decoder.h"
#include "arp_header.h"

/*    
Example for ex1b and ex1w - arrays in bytes and words respectively
ARP PACKET DETAILS 
     htype:     0x0001 
     ptype:     0x0800 
     hlen:      6  
     plen:      4 
     op:        1 
     spa:       192.168.1.51 
     sha:       01:02:03:04:05:06 
     tpa:       192.168.1.1 
     tha:       aa:bb:cc:dd:ee:ff 
*/
static u_int8_t ex1b[] = {0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
                         0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
                         0x05, 0x06, 0xc0, 0xa8, 0x01, 0x33, 
                         0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
                         0xc0, 0xa8, 0x01, 0x01}; 

static u_int16_t ex1w[] = {0x0001, 0x0800, 0x0604, 0x0001, 0x0102, 
                          0x0304, 0x0506, 0xc0a8, 0x0133, 0xaabb, 
                          0xccdd, 0xeeff, 0xc0a8, 0x0101};


/*
Assignment, what are ex2b, ext2w and ex3b, ext3w?
*/
static u_int8_t ex2b[] = {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 
                           0x00, 0x01, 0x12, 0xba, 0x34, 0x98, 
                           0x56, 0x76, 0xc0, 0xa8, 0x79, 0x90, 
                           0xa9, 0xb8, 0xc7, 0xd6, 0xe5, 0xf4, 
                           0x0a, 0x14, 0x28, 0xb8 };
static u_int16_t ex2w[] = {0x0001, 0x0800, 0x0604, 0x0001, 0x12ba, 
                          0x3498, 0x5676, 0xc0a8, 0x7990, 0xa9b8, 
                          0xc7d6, 0xe5f4, 0x0a14, 0x28b8 };

static u_int8_t ex3b[] = {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 
                           0x00, 0x01, 0x00, 0x40, 0x05, 0x56, 
                           0x4c, 0x00, 0x89, 0x8c, 0x32, 0x06, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x89, 0x8c, 0x32, 0x07 };
static u_int16_t ex3w[] = {0x0001, 0x0800, 0x0604, 0x0001, 0x0040,
                          0x0556, 0x4c00, 0x898c, 0x3206, 0x0000,
                          0x0000, 0x0000, 0x898c, 0x3207 };


/*
 * compile with .... gcc decoder.c -o decoder
 */
int main(int argc, char *argv[]) {
    arp_ether_ipv4 arp;
    char           output_buff[256] = "< NOTHING IN HERE YET >";

    bytesToArp(&arp, ex1b);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);

    wordsToArp(&arp, ex1w);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);

    bytesToArp(&arp, ex2b);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);

    wordsToArp(&arp, ex2w);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);

    bytesToArp(&arp, ex3b);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);

    wordsToArp(&arp, ex3w);
    arp_toString(&arp, output_buff, sizeof(output_buff) );
    printf("ARP PACKET BY BYTES\n %s \n", output_buff);
}

static void bytesToArp(arp_ether_ipv4 *arp, u_int8_t *buff){
    //This function accepts a pointer to a CHARACTER/BYTE buffer, in this case a byte buffer
    //It builds a arp_ether_ipv4 packet.  Notice a pointer to the structure
    //to copy the data into is passed as a pointer (e.g., *arp)
    arp->htype = buff[0] << 8 | buff[1];
    arp->ptype = buff[2] << 8 | buff[3];
    arp->hlen = buff[4];
    arp->plen = buff[5];
    arp->op = buff[6] << 8 | buff[7];
    memcpy(arp->sha, &buff[8], ETH_ALEN);
    memcpy(arp->spa, &buff[14], IP4_ALEN);
    memcpy(arp->tha, &buff[18], ETH_ALEN);
    memcpy(arp->tpa, &buff[24], IP4_ALEN);
}

static void wordsToArp(arp_ether_ipv4 *arp, uint16_t *buff){
    //This function accepts a pointer to a WORD buffer, in this case a byte buffer
    //It builds a arp_ether_ipv4 packet.  Notice a pointer to the structure
    //to copy the data into is passed as a pointer (e.g., *arp)
    arp->htype = buff[0];
    arp->ptype = buff[1];
    arp->hlen = (buff[2] >> 8) & 0xFF;
    arp->plen = buff[2] & 0xFF;
    arp->op = buff[3];
    for(int i = 0; i<3; i++){
        arp->sha[2*i] = (buff[4+i] >> 8) & 0xFF;
        arp->sha[2*i+1] = buff[4+i] & 0xFF;
    }
    for(int i = 0; i<2; i++){
        arp->spa[2*i] = (buff[7+i] >> 8) & 0xFF;
        arp->spa[2*i+1] = buff[7+i] & 0xFF;
    }
    for(int i = 0; i<3; i++){
        arp->tha[2*i] = (buff[9+i] >> 8) & 0xFF;
        arp->tha[2*i+1] = buff[9+i] & 0xFF;
    }
    for(int i = 0; i<2; i++){
        arp->tpa[2*i] = (buff[12+i] >> 8) & 0xFF;
        arp->tpa[2*i+1] = buff[12+i] & 0xFF;
    }
}




/*
 * This function accepts a pointer to an arp header, and formats it
 * to a printable string.  A buffer to dump this string is pointed
 * to with dstStr, and the length of the buffer is also passed in
 */
void  arp_toString(arp_ether_ipv4 *ap, char *dstStr, int len) {

    /*
    NOTE IN MY IMPLEMENTATION THE STRING I BUILT LOOKS LIKE THE BELOW
    YOU DONT EXACTLY NEED TO FORMAT YOUR OUTPUT THIS WAY BUT YOU SHOULD 
    INCLUDE ALL OF THE ARP FIELDS

    ARP PACKET DETAILS 
     htype:     0x0001 
     ptype:     0x0800 
     hlen:      6  
     plen:      4 
     op:        1 
     spa:       192.168.1.51 
     sha:       01:02:03:04:05:06 
     tpa:       192.168.1.1 
     tha:       aa:bb:cc:dd:ee:ff 
    */
    char spa_str[16], tpa_str[16], sha_str[18], tha_str[18];
    ip_toStr (ap->spa, spa_str, sizeof(spa_str));
    mac_toStr(ap->sha, sha_str, sizeof(sha_str));
    ip_toStr (ap->tpa, tpa_str, sizeof(tpa_str));
    mac_toStr(ap->tha, tha_str, sizeof(tha_str));
    snprintf(dstStr, len,
        "\thtype:\t0x%04x\n"
        "\t ptype:\t0x%04x\n"
        "\t hlen:\t%u\n"
        "\t plen:\t%u\n"
        "\t op:\t%u\n"
        "\t spa:\t%s\n"
        "\t sha:\t%s\n"
        "\t tpa:\t%s\n"
        "\t tha:\t%s",
        ap->htype, ap->ptype,
        ap->hlen, ap->plen, ap->op,
        spa_str,  sha_str,
        tpa_str,  tha_str);

}

/* ------------------------------------------------------------------------------------*/
/* Below are some helpers i am providing, you can use them or not use them if you want */
/* ------------------------------------------------------------------------------------*/

//Pase in a binary mac address, and convert it to a string, copy the string into the dst
//buffer.  Notice the check for 18 - thats because MAC strings are 17 characters and in
//C you need an extra byte for the null
int16_t mac_toStr(uint8_t *mac, char *dst, int len){
    //note max len is 17 plus add null byte 00-00-00-00-00-00\0
    if( len < 18) return -1;

    sprintf(dst,"%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}

uint16_t ip_toStr(u_int8_t *ip, char *dst, int len) {
    //note max len is 15 plus add null byte 255.255.255.255\0
    if( len < 16) return -1;

    sprintf(dst,"%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]); 
    return 0;
}


