#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

void call(u_char *none , const struct pcap_pkthdr *,  const u_char *);
void hostprint(u_char *td, int ll);
void printmac(u_int8_t a[]);

int main(int argc, char *argv[])
{
    char *dev = argv[1];          //argv[0]은 파일명이므로
    char errbuf[PCAP_ERRBUF_SIZE];
    struct in_addr net_addr, mask_addr;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    if(argc != 3)  //you must get 3 parameters
    {
        printf("you must enter 3 parameter!!\n");
        return 0;
    }
    printf("DEV = %s\n",dev);
    int ret;


    net_addr.s_addr  = netp;
    mask_addr.s_addr = maskp;
    ret=pcap_lookupnet(dev,&netp, &maskp, errbuf);
    if(ret==-1)
    {
        printf("%s\n",errbuf);
        return 1;
    }

    printf("===============================================\n");


    pcap_t *pcd;
    pcd = pcap_open_live(dev, 2048, 0 , 2000, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        return 0;
    }

    struct bpf_program fp; //패킷에 대한 필터를 만들어주는구조체

    if(pcap_compile(pcd, &fp, argv[2], 0, netp)==-1) //-- start here
    {
        printf("compile error\n");
        return -1;
    }

    if(pcap_setfilter(pcd,&fp)<0)
    {
        printf("setfilter error\n");
        return 0;
    }

    const u_char *pkt_data;
    struct pcap_pkthdr *header;

    int res;
    while((res=pcap_next_ex(pcd, &header, &pkt_data))>=0)
    {
        if(res==1)
        {
            call(0,header, pkt_data);
        }
        else if(res==0)
        {
            printf("time out error!!\n");
            continue;
        }
        else if(res==-1)
        {
            printf("error!!\n");
        }
        else if(res==-2)
        {
            printf("EOF");
        }
        else
            break;

    }

    pcap_close(pcd);
    return 0;
}


void call(u_char *none, const struct pcap_pkthdr *pkthdr, const u_char *packet)
   {
    (void)*none;

    unsigned short ether_type;
    int length=pkthdr->len;
    struct ether_header *ep = (struct ether_header *)packet;
    u_char *tcpdata;
    char ipsize[32];


    //MAC주소 정보
    printf("*************MAC Address Information*************\n");
    printf("Src MAC = ");
    printmac(ep->ether_shost);
    printf("Drc MAC = ");
    printmac(ep->ether_dhost);

    ether_type = ntohs(ep->ether_type);

    struct ip *iph;
    //IP정보
    if (ether_type == ETHERTYPE_IP) //0x0800
    {

        packet += sizeof(struct ether_header);
        iph = (struct ip *)((u_int8_t *)ep+sizeof(struct ether_header));
        //iph = (struct ip *)packet;
        printf("*************IP Address Information************* \n");
        printf("Version     : %d\n", iph->ip_v);
        inet_ntop(AF_INET, &(iph->ip_src), ipsize ,32);   //src address 32bit
        printf("Src Address : %s\n",ipsize);
        inet_ntop(AF_INET, &(iph->ip_dst), ipsize ,32);     //dst address 32bit
        printf("Dst Address : %s\n",ipsize);
        //TCP 정보
        struct tcphdr *tcph;
        printf("***************TCP Information***************\n");
        if (iph->ip_p == IPPROTO_TCP)
        {

            packet = packet + (iph->ip_hl * 4);
            tcph = (struct tcphdr *)((u_char*)iph + (iph->ip_hl * 4));
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
            tcpdata =(u_char *)(packet + (tcph->th_off * 4));
            printf("===============================================\n");

            int tdlength=length-sizeof(tcpdata);

            hostprint(tcpdata,tdlength);

            printf("\n");

             //패킷정보
            printf("Packet\n");
            int ch = 0;
            while(tdlength--)  //패킷의 오리지널 길이
            {

               printf("%02x ", *(tcpdata++)); //02x = 두 칸으로 16진수를 표기
               if((++ch % 16) == 0) //패킷부분을 볼때 보통 16진수를 16개를 한줄에 두기때문
                    printf("\n");
            }

        }
            else
        {
            printf("NO packet\n");
        }
            printf("\n\n");
            printf("===============================================\n");
     }
}

void hostprint(u_char * td,int ll) //호스트부분을 출력해주는 함수
{

        for( ;0<ll;ll--)
        {
             uint32_t *  host_start = (uint32_t*)td;
             if(*host_start == ntohl(0x486f7374))
             {
                 for( ;0<ll;ll--)
                 {
                     uint16_t * host_final = (uint16_t*)td;
                     printf("%c", *td);
                     td++;

                     if(*host_final == ntohs(0x0d0a))
                     break;
                  }
             }
             else
                 td++;
        }
}
void printmac(u_int8_t a[])
{
    int i;
    for (i = 0; i <= 5; i++)
    {
        printf(" %02x ",a[i]);
    }
    printf("\n");
}


//http://forum.falinux.com/zbxe/index.php?document_srl=433962&mid=C_LIB
//http://riny.tistory.com/135
//http://kaspyx.kr/14
