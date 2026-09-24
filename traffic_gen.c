#include <stdio.h>
#include <pcap.h>
#include<time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<string.h>
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#include <unistd.h>

// typedef unsigned char   u_int8;
// typedef unsigned short  u_int16;
// typedef unsigned int    u_int32;
// typedef unsigned long   u_int64;

// /*MAC头，总长度14字节 */
// typedef struct _eth_hdr{
    // u_int8 dst_mac[6];
    // u_int8 src_mac[6];
    // u_int16 eth_type;
// }eth_hdr;
// eth_hdr *ethernet;

// /*IP头*/
// typedef struct _ip_hdr{
    // u_int8 ver_hl;    //版本和头长
    // u_int8 serv_type; //服务类型
    // u_int16 pkt_len;  //包总长
    // u_int16 re_mark;  //重组标志
    // u_int16 flag_seg; //标志位和段偏移量
    // u_int8 surv_tm;    //生存时间
    // u_int8 protocol;  //协议码（判断传输层是哪一个协议）
    // u_int16 h_check;  //头检验和
    // u_int32 src_ip;   //源ip
    // u_int32 dst_ip;   //目的ip
    // u_int32 option;   //可选选项
// }ip_hdr;
// ip_hdr *ip;

// /*TCP头,总长度20字节，不包括可选选项*/
// typedef struct _tcp_hdr{
    // u_int16 sport;     //源端口
    // u_int16 dport;     //目的端口
    // u_int32 seq;       //序列号
    // u_int32 ack;       //确认序号
    // u_int8  head_len;  //头长度
    // u_int8  flags;     //保留和标记位
    // u_int16 wind_size; //窗口大小
    // u_int16 check_sum; //校验和
    // u_int16 urgent_p;  //紧急指针
// }tcp_hdr;
// tcp_hdr *tcp;

// /*UDP头，总长度8个字节*/
// typedef struct _udp_hdr{
    // u_int16 sport;     //源端口
    // u_int16 dport;     //目的端口
    // u_int16 pktlen;    //UDP头和数据的总长度
    // u_int16 check_sum; //校验和
// }udp_hdr;
// udp_hdr *udp;

// //ip整型转换点分十进制
// char *InttoIpv4str(u_int32 num){
    // char* ipstr = (char*)calloc(128, sizeof(char*)); 
  
    // if (ipstr)
        // sprintf(ipstr, "%d.%d.%d.%d", num >> 24 & 255, num >> 16 & 255, num >> 8 & 255, num & 255);
    // else
        // printf("failed to Allocate memory...");
    
    // return ipstr;
// }




void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
    
    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);
 
        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;
 
        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;
 
        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}

void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[3];
 
    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
    return ;
}
char* strstri(char * inBuffer, char * inSearchStr)
{
    char*  currBuffPointer = inBuffer;

    while (*currBuffPointer != 0x00)
    {
        char* compareOne = currBuffPointer;
        char* compareTwo = inSearchStr;
        //统一转换为小写字符
        while (tolower(*compareOne) == tolower(*compareTwo))
        {
            compareOne++;
            compareTwo++;
            if (*compareTwo == 0x00)
            {
                return (char*) currBuffPointer;
            }

        }
        currBuffPointer++; 
    }
    return NULL;
}
void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content){
    // int *id=(int *)arg;//记录包ID
    // printf("id=%d\n",++(*id));

    // printf("Packet length : %d\n",packet_header->len);
    // printf("Number of bytes : %d\n",packet_header->caplen);
    // printf("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    // ethernet = (struct _eth_hdr*)packet_content;
    // u_int64 src_mac = ntohs( ethernet->src_mac );
    // u_int64 dst_mac = ntohs( ethernet->dst_mac );
    // printf("src_mac:%lu\n",src_mac);
    // printf("dst_mac:%lu\n",dst_mac);
    // printf("eth_type:%u\n",ethernet->eth_type);
    
    char rcv_pkt[1516];
    printf("%d\n",packet_header->len);
    Hex2Str(packet_content,rcv_pkt,packet_header->len);
    printf("%s\n",rcv_pkt);
    
    // for(i=0;i<packet_header->caplen;i++){
        // printf(" %02x",packet_content[i]);
        // if((i+1)%16==0){
            // printf("\n");
        // }
    // }
    // printf("\n\n");
}

int main(int argc, char *argv[])
{
    //itf_s,l2_hd_s+self.pld_s,itf_r,self.chk_trf_timeout,self.check_value,self.ck_pkt_nc
    
    if (argc < 6)
    {
        return -1;
    }


    char errbuf[1024],snd_pkt[512],rcv_pkt[512];

    struct pcap_pkthdr packet_header;
    const unsigned char *packet_content = NULL;
    pcap_t *pcap_handle_tx=pcap_open_live(argv[1],1512,0,0,errbuf);
    if(pcap_handle_tx==NULL){
        printf("%s\n",errbuf);
        return -1;
    } 
    
    pcap_t *pcap_handle_rx=pcap_open_live(argv[3],1512,1,80,errbuf);
    if(pcap_handle_rx==NULL){
        printf("%s\n",errbuf);
        return -1;
    }
    pcap_setnonblock(pcap_handle_rx, 1, errbuf);
    
    // char *dev,filter_str[512],errbuf[1024],snd_pkt[500] ;
    // struct bpf_program filter;   

    // char *filter_str = "ether dst 00:e0:09:c1:0e:82 and ";  //过滤条件
    // sprintf(filter_str,"ether dst %s and ether src %s",argv[3],argv[4]);

    //us:./cap eth-nt 10 10:10:10:00:00:02 10:10:10:52:d0:0a eth-onu
    // char *org_pkt="10101000000210101052d00a8100000a08004500004e00000000400600001052d00a0a000000000000000001aaaa00000000c0aaaaaadc08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    //ds ./cap eth-onu 10 10:10:10:52:d0:0a 10:10:10:00:00:02  eth-nt
    // char *org_pkt="10101052d00a101010000002810000c808004500004e00000000400600000a0000001052d00a000000000001aaaa00000000c0aaaaaadc08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    HexStrToByte(argv[2],snd_pkt,strlen(argv[2]));
	int i_send_cnt = 1;
	if (strlen(argv[6])<10)
	{
		i_send_cnt = atoi(argv[6]);
	}
		
    while(i_send_cnt--)
	{
		if (pcap_sendpacket(pcap_handle_tx, snd_pkt, strlen(argv[2])/2) != 0)
		{
			pcap_close(pcap_handle_tx);
			printf("%s\n", pcap_geterr(pcap_handle_tx));
			return -1;
		}
	}
    pcap_close(pcap_handle_tx);
	
    /*
    int k;
    for(k=0;k<(strlen(org_pkt)/2);k++)
	{
		printf("convert after:%d, %02x\n", strlen(snd_pkt),snd_pkt[k]); 
	}
    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char *dev_ip,*dev_mask;

    if(pcap_lookupnet(dev,&ipaddress,&ipmask,errbuf)==-1){
        printf("%s\n",errbuf);
        return 0;
    }

    addr.s_addr=ipaddress;
    dev_ip=inet_ntoa(addr);
    printf("ip address : %s\n",dev_ip);

    addr.s_addr=ipmask;
    dev_mask=inet_ntoa(addr);
    printf("netmask : %s\n",dev_mask);

    printf("---------packet--------\n");
    int id=0;//传入回调函数记录ID*/
    
    /*Compiling and setting filtering conditions*/
    // if(pcap_compile(pcap_handle_rx,&filter,filter_str,1,0)== -1 || pcap_setfilter(pcap_handle_rx, &filter) == -1)
    // {
        // printf("set pkt filter error...\n");
        // return 1;
    // }


    int i;
    for(i=0;i<(atoi(argv[4]));i++)
    {
        usleep(80000);
        packet_content = pcap_next(pcap_handle_rx,&packet_header);
        if (packet_content == NULL)
        {
            continue;
        }

        Hex2Str(packet_content,rcv_pkt,packet_header.len);
        if (strstri(rcv_pkt,argv[5])&&( strlen(argv[6])<10 || strstri(rcv_pkt,argv[6])==NULL))
        {
            printf("%s\n",rcv_pkt);
            pcap_close(pcap_handle_rx);
            return 0;
        }
    }
        // if(pcap_dispatch(pcap_handle_rx,-1,pcap_callback,NULL)>0)
        // {
            // printf("success\n");
            // pcap_close(pcap_handle_rx);
            // return 0;
        // }
    pcap_close(pcap_handle_rx);        
    return 1;
}
