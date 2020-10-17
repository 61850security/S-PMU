#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/*Keep the destination MAC address 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF in case of broadcast */
/* Keep your intended destination MAC here*/
#define DEST_MAC0    0xFF
#define DEST_MAC1    0xFF
#define DEST_MAC2    0xFF
#define DEST_MAC3    0xFF
#define DEST_MAC4    0xFF
#define DEST_MAC5    0xFF


#define IF_NAME     "device_MAC_address"
#define B_SIZE     2048
/* IP Header fields */
char ver_hl =0x45;  // version 4 and header length of ip is 20 (5) bytes (1 byte)
char tos = 0x00; // type of service. IP precedence and Differentiated Service code point (1 byte)
char totlen1 = 0x00; // Total length of the packet (header 20 + udp packet size 96)=116 (2 bytes)
char totlen2 = 0x74;                    
char identification1 = 0x6B; // unique identification of each packet (2 bytes) 
char identification2 = 0xA1;
char frag_off1 = 0x00; //if the packets are fragmented, then this field will be used. (2 bytes)
char frag_off2 = 0x00;
char ttl = 0x80; // time to live (1 byte)
char protocol = 0x11; // next protocol in the sequence UDP (1 byte)
char hdrchks1 = 0x00; // header check sum (2 bytes)
char hdrchks2 = 0x00;

// source IP address (4 bytes)
char srcaddr0 = 0xC0; 
char srcaddr1 = 0xA8; 
char srcaddr2 = 0x01; 
char srcaddr3 = 0x0A; 

// destination IP address (4 bytes)
char dstaddr0 = 0xC0; 
char dstaddr1 = 0xA8; 
char dstaddr2 = 0x01; 
char dstaddr3 = 0x03; 

/* UDP Header fields */
char srcport1 = 0xDA;
char srcport2 = 0xD1;

char dstport1 = 0xDA;
char dstport2 = 0x66;

char lengt1= 0x00;
char lengt2 = 0x60; /* length of udp header 8 + udp pay load size 88 = 96 */  

char chksum1 = 0xD7;
char chksum2 = 0x3B;  

/* IEEE C37.118.2 data frame with security fields */ 
char sync_word1=0xAA;	/* Synchronization word 2 bytes  */
char sync_word2=0x82;   /* (1000 0010 => 1: security, 000: data frame, 0010: fixed for this standard) */

char frame_size1=0x00;	/* Total number of bytes in the frame, including CHK (2 bytes) 56 bytes + 32 bytes= 88 bytes */
char frame_size2=0x58;

char sa1=0x00; /* 0x00: No Encryption*/
               /* Encryption algorithms used AES128-GCM 0x01, AES256-GCM 0x02: IDcode to digital fields */
char sa2=0x03; /* 0x03: HMAC-SHA256 */
                  /* authentication algorithm used HMAC-SHA256 0x03 , None 0x00, HMAC-SHA256-80 0x01, HMAC-SHA256-128 0x02, 
                  AES-GMAC-64 0x04, AES-GMAC-128 0x05: From Sync to digital fields*/

char TimeofPresentKey1=0x5B;  /* hexadecimal timestamp/epoch */
char TimeofPresentKey2=0xFC;  /* Tuesday, November 27, 2018 4:48:00 PM */
char TimeofPresentKey3=0x5D;
char TimeofPresentKey4=0xA2;

char TimeofNextKey1=0xFC;
char TimeofNextKey2=0xA1; /* 60 minutes for time of next key */


char iv; /* no iv in HMAC-SHA256 */

char PMUID1=0x00;		/* PMU ID number 2 bytes*/
char PMUID2=0x3C;

char soc1=0x5E;			/* Seconds of century */
char soc2=0x00;
char soc3=0xB7;
char soc4=0x47;

char Time_quality_flag=0x00;	/* fraction of seconds 4 bytes*/
char fraction_of_seconds1=0x08;
char fraction_of_seconds2=0xd9;
char fraction_of_seconds3=0xa0;

char stat1=0x00; 		/* STAT 2 bytes*/
char stat2=0x00;

char phasors1=0x42;		/* phasors 24 bytes*/
char phasors2=0xc8;
char phasors3=0x27;
char phasors4=0xb9;
char phasors5=0xbf;
char phasors6=0xc8;
char phasors7=0x9e;
char phasors8=0xc2;

char phasors9=0x42;
char phasors10=0xc7;
char phasors11=0xe4;
char phasors12=0x79;
char phasors13=0x40;
char phasors14=0x27;
char phasors15=0xad;
char phasors16=0x27;

char phasors17=0x42;
char phasors18=0xc8;
char phasors19=0x05;
char phasors20=0x11;
char phasors21=0x3f;
char phasors22=0x06;
char phasors23=0xbe;
char phasors24=0xb0;

char freq_deviation1=0x00;	/* Frequency deviation nominal 2 bytes */
char freq_deviation2=0x00;

char rocof1=0x00;		/* rate of change of frequency 2 bytes*/
char rocof2=0x00;

char dsw1=0x00;			/* digital status word 2 bytes */
char dsw2=0x00;


char chk1=0xFD;		/* check sum 2 bytes */ 		
char chk2=0xBA;

unsigned char Data[100]; // to convert into string format 
unsigned char signature_data[50]=
				{
				  0x02, 0x03, 0x5B, 0xFC, 0x5D, 0xA2, 0xFC, 0xA1, 0x00, 0x3C, 0x48, 0x93,
					0x37, 0x43, 0x00, 0x08, 0xd9, 0xa0, 0x00, 0x00, 0x42, 0xc8, 0x27, 0xb9,
					0xbf, 0xc8, 0x9e, 0xc2, 0x42, 0xc7, 0xe4, 0x79, 0x40, 0x27, 0xad, 0x27,
					0x42, 0xc8, 0x05, 0x11, 0x3f, 0x06, 0xbe, 0xb0, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00
				};  //updated 

int main(int argc, char *argv[])
{
    int sfd;
    int i=0,j=0;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len;
    unsigned char sendbuf[B_SIZE],Data[82];
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];
    unsigned char key[32]= { 0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
                             0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f};
    unsigned char *hash;
    double begin, end, time_gen;
    /* Get interface name */
    strcpy(ifName, IF_NAME);

    /* Open RAW socket to send on */
    if ((sfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        perror("socket");
    }
    
    /* clear the struct ifreq if_idx with memset system call */
    memset(&if_idx, 0, sizeof(struct ifreq));

    /* copy interface name into struct ifreq if_idx */
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);

    /* configure the interface index */ 
    if (ioctl(sfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
     
	//converting hexadecimal values into string format for giving input to hmac function    
    for ( j=0; j<50; j++)
    {
	      sprintf( &(Data[j * 2]) , "%02x", signature_data[j]); 
        //printf(" %s",Data);
    }
    begin = clock();
    hash = HMAC(EVP_sha256(), key, strlen((char *)key), Data, strlen((char *) Data), NULL, NULL);
    end = clock();

    begin = clock();
    hash = HMAC(EVP_sha256(), key, strlen((char *)key), Data, strlen((char *) Data), NULL, NULL);
    end = clock();
    time_gen= (double)(end - begin) / CLOCKS_PER_SEC;
	
    printf("\n mac generation time= %lf\n",time_gen*1000);
    
    // Loop forever
    while(1) {

        /* Buffer of BUF_SIZ bytes we'll construct our frame in.
           First, clear it all to zero. */
        memset(sendbuf, 0, B_SIZE);
        tx_len = 0;

        /* Construct the UDP header */

        /* Destination MAC address */
        sendbuf[tx_len++] = DEST_MAC0;
        sendbuf[tx_len++] = DEST_MAC1;
        sendbuf[tx_len++] = DEST_MAC2;
        sendbuf[tx_len++] = DEST_MAC3;
        sendbuf[tx_len++] = DEST_MAC4;
        sendbuf[tx_len++] = DEST_MAC5;

        /* keep your source device MAC address here */
        /* Source MAC address */
        sendbuf[tx_len++] = 0xXX;
        sendbuf[tx_len++] = 0xXX;
        sendbuf[tx_len++] = 0xXX; 
        sendbuf[tx_len++] = 0xXX; 
        sendbuf[tx_len++] = 0xXX; 
        sendbuf[tx_len++] = 0xXX; 


        /* Ethertype field IP protocol */
        sendbuf[tx_len++] = 0x08;
        sendbuf[tx_len++] = 0x00;

        /*  PDU fields */
        sendbuf[tx_len++] = ver_hl;                  
        sendbuf[tx_len++] = tos; 

        sendbuf[tx_len++] = totlen1;                 
        sendbuf[tx_len++] = totlen2;

        sendbuf[tx_len++] = identification1;
		    sendbuf[tx_len++] = identification2; 
                  
		    sendbuf[tx_len++] = frag_off1;
        sendbuf[tx_len++] = frag_off2; 
                 
        sendbuf[tx_len++] = ttl;
        sendbuf[tx_len++] = protocol;

        sendbuf[tx_len++] = hdrchks1;
        sendbuf[tx_len++] = hdrchks2;

        sendbuf[tx_len++] = srcaddr0;
        sendbuf[tx_len++] = srcaddr1;
        sendbuf[tx_len++] = srcaddr2;
        sendbuf[tx_len++] = srcaddr3;

        sendbuf[tx_len++] = dstaddr0;
        sendbuf[tx_len++] = dstaddr1;
        sendbuf[tx_len++] = dstaddr2;
        sendbuf[tx_len++] = dstaddr3;

        sendbuf[tx_len++] = srcport1;
        sendbuf[tx_len++] = srcport2;

        sendbuf[tx_len++] = dstport1;
		    sendbuf[tx_len++] = dstport2;

		    sendbuf[tx_len++] = lengt1;
		    sendbuf[tx_len++] = lengt2;

        sendbuf[tx_len++] = chksum1;
		    sendbuf[tx_len++] = chksum2;
	
        sendbuf[tx_len++] = sync_word1;
		    sendbuf[tx_len++] = sync_word2;

        sendbuf[tx_len++] = frame_size1;
		    sendbuf[tx_len++] = frame_size2;

		    sendbuf[tx_len++] = sa1;
		    sendbuf[tx_len++] = sa2; 
	
		    sendbuf[tx_len++] = TimeofPresentKey1;
		    sendbuf[tx_len++] = TimeofPresentKey2; 
		    sendbuf[tx_len++] = TimeofPresentKey3;
		    sendbuf[tx_len++] = TimeofPresentKey4;
		    sendbuf[tx_len++] = TimeofNextKey1;
		    sendbuf[tx_len++] = TimeofNextKey2;
	

		    sendbuf[tx_len++] = PMUID1;
		    sendbuf[tx_len++] = PMUID2;

  		  sendbuf[tx_len++] = soc1;
		    sendbuf[tx_len++] = soc2;
		    sendbuf[tx_len++] = soc3;
		    sendbuf[tx_len++] = soc4;

		    sendbuf[tx_len++] = Time_quality_flag;
		    sendbuf[tx_len++] = fraction_of_seconds1;
		    sendbuf[tx_len++] = fraction_of_seconds2;
		    sendbuf[tx_len++] = fraction_of_seconds3;

        sendbuf[tx_len++] = stat1;
		    sendbuf[tx_len++] = stat2;

		    sendbuf[tx_len++] = phasors1;
		    sendbuf[tx_len++] = phasors2;
		    sendbuf[tx_len++] = phasors3;
		    sendbuf[tx_len++] = phasors4;
    		sendbuf[tx_len++] = phasors5;
    		sendbuf[tx_len++] = phasors6;
    		sendbuf[tx_len++] = phasors7;
    		sendbuf[tx_len++] = phasors8;
    		sendbuf[tx_len++] = phasors9;
    		sendbuf[tx_len++] = phasors10;
    		sendbuf[tx_len++] = phasors11;
    		sendbuf[tx_len++] = phasors12;
    		sendbuf[tx_len++] = phasors13;
    		sendbuf[tx_len++] = phasors14;
    		sendbuf[tx_len++] = phasors15;
    		sendbuf[tx_len++] = phasors16;
    		sendbuf[tx_len++] = phasors17;
    		sendbuf[tx_len++] = phasors18;
    		sendbuf[tx_len++] = phasors19;
    		sendbuf[tx_len++] = phasors20;
    		sendbuf[tx_len++] = phasors21;
    		sendbuf[tx_len++] = phasors22;
    		sendbuf[tx_len++] = phasors23;
    		sendbuf[tx_len++] = phasors24;

    		sendbuf[tx_len++] = freq_deviation1;	
    		sendbuf[tx_len++] = freq_deviation2;

    		sendbuf[tx_len++] = rocof1;
    		sendbuf[tx_len++] = rocof2;

    		sendbuf[tx_len++] = dsw1;
    		sendbuf[tx_len++] = dsw2;
    		
    		for (j = 0; j < 32 ; j++)
    			sendbuf[tx_len++] =hash[j];
    		
		
    		sendbuf[tx_len++] = chk1;
    		sendbuf[tx_len++] = chk2;


    		/* Frame Check Sequence fields */
    		sendbuf[tx_len++] = 0xD4;
    		sendbuf[tx_len++] = 0x76;
    		sendbuf[tx_len++] = 0x2B;
    		sendbuf[tx_len++] = 0x79; 

    		/* Index of the network device */
            socket_address.sll_ifindex = if_idx.ifr_ifindex;  /* Network Interface number */

        /* Address length*/
        socket_address.sll_halen = ETH_ALEN; /* Length of Ethernet address */

        /* Destination MAC */
        socket_address.sll_addr[0] = DEST_MAC0;
        socket_address.sll_addr[1] = DEST_MAC1;
        socket_address.sll_addr[2] = DEST_MAC2;
        socket_address.sll_addr[3] = DEST_MAC3;
        socket_address.sll_addr[4] = DEST_MAC4;
        socket_address.sll_addr[5] = DEST_MAC5;

        /* Send packet */
        if (sendto(sfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
        else {
            printf("Sent :");
            for (i=0; i < tx_len; i++)
                printf("%02x:", sendbuf[i]);
            printf("\n");
        }
        /* Wait specified number of microseconds
           1,000,000 microseconds = 1 second
           */
        usleep(1000000);
    }
    return 0;
}


