
/* compile it like: gcc pcapfilter.c -o pcapfilter.o -lpcap */

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

int main(int argc, char *argv[])
{
  pcap_t *handle;			/* Session handle */
  char *dev = "wlan0";			/* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct bpf_program fp;		/* The compiled filter */
  //char filter_exp[] = "udp and (src port 30036 or 30038 or 30040)";	/* The filter expression */
  char filter_exp[100] ;	/* The filter expression */
  bpf_u_int32 mask;		/* Our netmask */
  bpf_u_int32 net;		/* Our IP */
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */
 
  // input parameters related variables
  struct udphdr *udphd ;
  struct iphdr *iphd ;
  unsigned char* payload;
  int dimension = 1;
  int portPl;
  int portFec1;
  int portFec2;
  char pcapF[256];
  int port ;
  FILE* pl = NULL;
  FILE* f1 = NULL;
  FILE* f2 = NULL;
  FILE* details = NULL;
  int i,j;
  // fec related variables
  int SSrc = -1;
  int ssrc ;
  int seqPl = -1;
  int seqF1 = -1;
  int seqF2 = -1;
  bool sync =false;
  bool syncPl =false;
  bool syncF1 =false;
  bool syncF2 =false;
  int seq,snb,snbc,snbr,offset,NA;
 
  if (argc < 3 || argc > 5) { 
    fprintf(stderr,"Invalid arguments\n");
    return(0);
  }
  // read in the input parameters.
  strncpy(pcapF,argv[1],255);
  pcapF[256] = '\0';
  dimension = argc-3;
  portPl = atoi(argv[2]);
  pl = fopen("payload.tmp","w");  
  if(dimension > 0) {
    portFec1 = atoi(argv[3]);
    f1 = fopen("fec1.tmp","w");  
  }
  if (dimension > 1) {
    portFec2 = atoi(argv[4]);
    f2 = fopen("fec2.tmp","w");
  }  
  details = fopen("tmp123.tmp","w");

  // create the filter string.
  if (dimension == 2) 
   sprintf(filter_exp,"udp and (dst port %d or %d or %d)",portPl,portFec1,portFec2);
  else if (dimension == 1)
   sprintf(filter_exp,"udp and (dst port %d or %d )",portPl,portFec1);  
  else 
   sprintf(filter_exp,"udp and (dst port %d )",portPl);  
  fprintf(stderr,"Filter:%s \n",filter_exp);
  
  /* Open the session in promiscuous mode */
  handle = pcap_open_offline(pcapF, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open pcap file:%s  error:%s\n",pcapF,errbuf);
    return(2);
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  seq = 64*1024 +1;
  fprintf(pl,"%d\n",seq); 
  while (1) {
    /* Grab a packet */
    packet = pcap_next(handle, &header);
    if (packet == NULL)
      break;
    //TODO calculate ip header dynamically
    payload = (unsigned char*)(packet+14+20);
    // get udp port number
    port = (payload[2] << 8 | payload[3]);
    // point to rtp payload
    payload = (unsigned char*)(packet+14+20+8);

    seq = (payload[2] << 8 | payload[3]);
    ssrc = ( payload[8] << 24 | payload[9] << 16 | payload[10] << 8 | payload[11]);

    //syncronization logic to capture only required pcakets whcih make sense.
    if (sync == false && ssrc == SSrc) {
      if (syncPl==false && port == portPl) {
        if (seq == seqPl || (seq > seqPl && (seq-seqPl)<100 ) || (seqPl -seq ) > 64000)
          syncPl = true;
      }
      if (syncF1==false && port == portFec1 && dimension > 0) {
        if (seq == seqF1 || (seq > seqF1 && (seq-seqF1)<100 ) || (seqF1 -seq ) > 64000)
          syncF1 = true;
      }
      if (syncF2==false && port == portFec2 && dimension > 1) {
        if (seq == seqF2 || (seq > seqF2 && (seq-seqF2)<100 ) || (seqF2 -seq ) > 64000)
          syncF2 = true;
      }
      if (syncPl && syncF1 && syncF2)
        sync = true;
    }

    // write the synchrozied seq numbers in to file
    if (ssrc == SSrc) {
      if (syncPl==true && port == portPl) fprintf(pl,"%d\n",seq);
      if (syncF1==true && port == portFec1 && dimension > 0) fprintf(f1,"%d\n",seq);
      if (syncF2==true && port == portFec2 && dimension > 1) fprintf(f2,"%d\n",seq);
    }

    // handle new discontinuity
    if (ssrc != SSrc && sync == true) {
      sync=syncPl=syncF1=syncF2=false;
      seqPl=seqF1=seqF2=-1;
      seq = 64*1024 +1;
      fprintf(pl,"%d\n",seq); 
    }
    // handle initial entry
    if (ssrc!= SSrc && sync == false) {
      if (dimension == 0) { SSrc= ssrc; sync=syncPl=true; }
      else if (dimension == 1) {
        if (port != portFec1) continue;
        snb = (payload[12] << 8 | payload[13]);
        seqPl = (snb+100-1) % (64*1024) ; 
        offset = payload[25];
        NA=payload[26];
        seqF1 = (seq +offset) % (64*1024);
        fprintf(f1,"%d\n",seqF1); 
        fprintf(pl,"%d\n",seqPl); 
        SSrc = ssrc;
        //printf ("seqpl:%d , seqc:%d \n",seqPl,seqF1);
        fprintf(details,"%d %d %d \n",dimension,NA,offset); 
      }
      else if (dimension == 2) {
        if (port == portPl) continue;
        snb = (payload[12] << 8 | payload[13]);
        if (port == portFec2 ) { seqF2 = seq; snbr = snb; NA=payload[26];}
        if (port == portFec1 ) { seqF1 = seq; snbc = snb;}
        if (seqF1 != -1 && seqF2 != -1 ) {
          for (i = 0 ; i< 20 ; i++) {
            if ((snbr-NA*i) > 0 &&  (snbc - (snbr-NA*i)) < NA && (snbc - (snbr-NA*i)) > 0 ) {
              seqPl = ((snbr- NA*i)+200 ) % (64*1024);
              seqF2 = ((200/NA-i)+ seqF2) % (64*1024);
              seqF1 = ((2*NA-(snbc - (snbr-NA*i)))+ seqF1) % (64*1024);
              SSrc = ssrc;
              //printf ("seqpl:%d , seqr:%d seqc:%d \n",seqPl,seqF2,seqF1);
              fprintf(f2,"%d\n",seqF2); 
              fprintf(f1,"%d\n",seqF1); 
              fprintf(pl,"%d\n",seqPl); 
              fprintf(details,"%d %d %d \n",dimension,100/NA,NA); 
              break;
            }
          }
        }
      }
    }
    /* Print its length */
  }
  /* And close the session */
  printf("\nPayload and Fec packets ready for processing\n");
  pcap_close(handle);
  fclose(pl);
  fclose(details);
  if (f1 != NULL) 
    fclose(f1);
  if (f2 != NULL) 
    fclose(f2);
  return(0);
}

