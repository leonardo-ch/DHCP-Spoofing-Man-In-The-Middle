//General
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include <time.h>
#include <unistd.h>
//headers
#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <netinet/in_systm.h> //tipos de dados
//protocols
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
//headers
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
//system
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

void tokenize(char* linne);
void ProcessPacket(unsigned char* , int);
void Make_header();
void Make_footer();
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

FILE *fp;
struct sockaddr_in source,dest;
int tcp=0,udp=0,igmp=0,total=0,others=0,i,j;

struct ifreq ifr;
char interfacename[IFNAMSIZ];

unsigned char *ip;
unsigned char *ip_name;

int main(int argc,char *argv[])
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    if (argc != 3) {
  		printf("Usage: %s interface tempo-de-execucao\n", argv[0]);
  		return 1;
  	}
  	strcpy(interfacename, argv[1]);


    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    fp=fopen("out.html","w");
    if(fp==NULL)
    {
        printf("Unable to create out.html file.");
    }
    printf("Starting...\n");

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
  	strcpy(ifr.ifr_name, interfacename);
  	if(ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0)
  		printf("erro no ioctl!");
  	ioctl(sock_raw, SIOCGIFFLAGS, &ifr);
  	ifr.ifr_flags |= IFF_PROMISC;
  	ioctl(sock_raw, SIOCSIFFLAGS, &ifr);

    /*Define variáveis para controle do tempo */
  	time_t espera;
  	time_t start = time(NULL);
  	time_t seconds = atoi(argv[2]);
  	espera = start + seconds;

    Make_header();
    while (start < espera) {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    		start = time(NULL);
    }
    Make_footer();
    close(sock_raw);
    printf("Finished\n");
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:  //TCP Protocol
            ++tcp;
              print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d  Others : %d   Total : %d\r", tcp , udp , others , total);
}

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(fp , "\n");
    fprintf(fp , "Ethernet Header\n");
    fprintf(fp , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(fp , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(fp , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    //print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;



    //fprintf(fp , "\n");
    //fprintf(fp , "IP Header\n");
    //fprintf(fp , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    //fprintf(fp , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    //fprintf(fp , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    //fprintf(fp , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    //fprintf(fp , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(fp , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(fp , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(fp , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    //fprintf(fp , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    //fprintf(fp , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    //fprintf(fp , "   |-Checksum : %d\n",ntohs(iph->check));
    //ip = inet_ntoa(source.sin_addr);
    fprintf(fp, " - %s", inet_ntoa(source.sin_addr));
    //fprintf(fp , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    unsigned char* dataPayload = Buffer + header_size;
	  unsigned char *dataTextPayload = malloc(60000);

    int i , j;
    for(i=0 ; i < (Size - header_size) ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            for(j=i-16 ; j<i ; j++)
            {
                if(dataPayload[j]>=32 && dataPayload[j]<=128)
                    sprintf(dataTextPayload + strlen(dataTextPayload) , "%c",(unsigned char)dataPayload[j]); //if its a number or alphabet
                else if(dataPayload[j]==13)
                    sprintf(dataTextPayload + strlen(dataTextPayload) , "\r");
                else if(dataPayload[j]==10)
                    sprintf(dataTextPayload + strlen(dataTextPayload) , "\n");
                else sprintf(dataTextPayload + strlen(dataTextPayload) , ".");
            }
        }
    }
    if((strstr(dataTextPayload, "Referer:") != NULL) && ntohs(tcph->dest) == 80){
      fprintf(fp, "\n<li>");

      time_t t = time(NULL);
      struct tm tm = *localtime(&t);

      fprintf(fp, "%d-%d-%d %d:%d:%d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

      print_ip_header(Buffer,Size);
      //fprintf(fp, " - %s", ip);
      fprintf(fp, " (Example-PC) ");
      // fprintf(fp , "\n");
      // fprintf(fp , "TCP Header\n");
      //fprintf(fp , "   |-Source Port      : %u\n",ntohs(tcph->source));
      //fprintf(fp , "   |-Destination Port : %u\n",);
      // fprintf(fp , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
      // fprintf(fp , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
      //fprintf(fp , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
      // //fprintf(fp , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
      // //fprintf(fp , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
      // fprintf(fp , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
      // fprintf(fp , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
      // fprintf(fp , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
      // fprintf(fp , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
      // fprintf(fp , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
      // fprintf(fp , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
      // fprintf(fp , "   |-Window         : %d\n",ntohs(tcph->window));
      // fprintf(fp , "   |-Checksum       : %d\n",ntohs(tcph->check));
      // fprintf(fp , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
      // fprintf(fp , "\n");
      // fprintf(fp , "                        DATA Dump                         ");
      //fprintf(fp , "\n");

      //fprintf(fp , "IP Header\n");
      //PrintData(Buffer,iphdrlen);

      //fprintf(fp , "TCP Header\n");
      //PrintData(Buffer+iphdrlen,tcph->doff*4);

      //fprintf(fp , "Data Payload\n");
      fprintf(fp, "<a href = \"");
      tokenize(dataTextPayload);
      fprintf(fp, "</a></li>");
      //PrintData(dataPayload , Size - header_size );

      memset(dataPayload,0,strlen(dataPayload));
      memset(dataTextPayload,0,strlen(dataTextPayload));
    }
}

void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    // fprintf(fp , "\n\n***********************UDP Packet*************************\n");
    //
    if(ntohs(udph->source) == 53)
      print_ip_header(Buffer,Size);
    //
    // // fprintf(fp , "\nUDP Header\n");
    // // fprintf(fp , "   |-Source Port      : %d\n" , ntohs(udph->source));
    // // fprintf(fp , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    // fprintf(fp , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    // // fprintf(fp , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    //
    // fprintf(fp , "\n");
    // // fprintf(fp , "IP Header\n");
    // // PrintData(Buffer , iphdrlen);
    //
    // fprintf(fp , "UDP Header\n");
    // PrintData(Buffer+iphdrlen , sizeof udph);
    //
    // fprintf(fp , "Data Payload\n");
    //
    // //Move the pointer ahead and reduce the size of string
    // PrintData(Buffer + header_size , Size - header_size);

    //fprintf(fp , "\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(fp , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fp , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(fp , "."); //otherwise print a dot
            }
            fprintf(fp , "\n");
        }

        if(i%16==0) fprintf(fp , "   ");
            fprintf(fp , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(fp , "   "); //extra spaces
            }

            fprintf(fp , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(fp , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(fp , ".");
                }
            }

            fprintf(fp ,  "\n" );
        }
    }
}

void Make_header(){
	fprintf(fp, "<html>\n");
  fprintf(fp, "<header>\n");
	fprintf(fp, "<title>Historico de Navegacao</title>\n");
	fprintf(fp, "</header>\n");
	fprintf(fp, "<body>\n");
	fprintf(fp, "<ul>\n");
}

void Make_footer(){
	fprintf(fp, "\n</ul>\n");
	fprintf(fp, "</body>\n");
	fprintf(fp, "</html>\n");
}

void tokenize(char* line)
{
   char* cmd = strtok(line,"\n");

   while(cmd != NULL){
     if(strstr(cmd, "Referer: ") != NULL){
      fprintf(fp, "%s\">%s", cmd+9, cmd+9);
      break;
     }
   cmd = strtok(NULL, "\n");
   }

}
