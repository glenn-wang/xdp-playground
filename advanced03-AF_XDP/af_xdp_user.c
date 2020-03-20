/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>

#include <linux/ipv6.h>
#include <linux/icmpv6.h>

// #include <linux/ip.h>
#include <linux/icmp.h>

// #include <linux/udp.h>
#include <netinet/ip.h>

#include <sys/types.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"


/* --------merge header begin-------------- */


// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>           // close()
// #include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
// #include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
// #include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_UDP, INET_ADDRSTRLEN
// #include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)

#include <netinet/udp.h>      // struct udphdr
// #include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
// #include <net/if.h>           // struct ifreq
// #include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

// #include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t udp4_checksum (struct iphdr, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);


/* --------merge header end-------------- */


#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);

	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

int ipv4_num = 0;
int ipv6_num = 0;

struct hdr_cursor {
	void *pos;
};

int parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	// int hdrsize = sizeof(*eth);

	nh->pos  = eth + 1;

	*ethhdr = eth;

	return ntohs(eth->h_proto);
}

int parse_iphdr(struct hdr_cursor *nh, struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = iph->ihl * 4;

	nh->pos += hdrsize;

	*iphdr = iph;

	return iph->protocol;
}

int parse_udphdr(struct hdr_cursor *nh, struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	nh->pos = h + 1;

	*udphdr = h;

	len = ntohs(h->len) - sizeof(struct udphdr);

	if (len < 0)
		return -1;

	return len;
}

typedef struct
{
    unsigned int num;
    char msg[50];
    char msg2[50];
    double socre;
} My_UDP;

int parse_test_body(struct hdr_cursor *nh)
{

    // 接收结构体 
    // My_UDP *my_content = (My_UDP *)(nh->pos);
    // printf("\nmsg: %s", my_content->msg);
    // printf("\nmsg2: %s", my_content->msg2);
    // printf("\nnum: %d", (my_content->num));
    // printf("\nnum: %f\n\n", (my_content->socre));

    //  接收字符串
	char *buffer = (char *)(nh->pos);

	printf("\nContent: %s\n\n", (buffer));


	return 0;
}

//  checksum
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    unsigned int sum = 0, nleft = len;
    unsigned short answer = 0;
    unsigned short *w = addr;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);//将高16bit与低16bit相加

    sum += (sum >> 16);//将进位到高位的16bit与低16bit 再相加
    answer = (unsigned short)(~sum);
    return (answer);
}

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

// uint8_t *ether_frame;


static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{

	int ip_type, proto_type;

	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

        /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

 
	struct ethhdr *eth = (struct ethhdr *) pkt;

	// 获取从二层头获取三层协议名称
	// int eth_type = ntohs(eth->h_proto);


	struct hdr_cursor nh = { .pos = pkt };

	ip_type = parse_ethhdr(&nh, &eth);


	if(ip_type == ETH_P_IPV6){
		// IPv6
		printf("\nIPv6 eth_type = 0x%04X num: %d\n", ip_type, ++ipv6_num);
		if (ipv6_num & 1)
		{
			return false;
		}
		
		// return false;

	} 
	else if(ip_type == ETH_P_IP)
	{
		// IPv4
		printf("\nIPv4 IP_type = 0x%04X num: %d\n", ip_type, ++ipv4_num);

		struct iphdr *iphdr;

		proto_type = parse_iphdr(&nh, &iphdr);

		if (proto_type == IPPROTO_UDP)
		{
			printf("\nIPv4 UDP proto_num: %d\n", proto_type);

			struct udphdr *udphdr;

			if (parse_udphdr(&nh, &udphdr) < 0)
			{
				return false;
			}
			else
			{
				printf("\nIPv4 UDP dest port: %d\n", ntohs(udphdr->dest));

				parse_test_body(&nh);

				// uint8_t tmp_mac[ETH_ALEN];
			    // struct in_addr tmp_ip;
				// u_int16_t tmp_port = 0;

/*
                //  mac 地址交换
				memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
			    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
			    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

				//  IP 地址交换
			    memcpy(&tmp_ip, &iphdr->saddr, sizeof(tmp_ip));
			    memcpy(&iphdr->saddr, &iphdr->daddr, sizeof(tmp_ip));
			    memcpy(&iphdr->daddr, &tmp_ip, sizeof(tmp_ip));

                //  端口 交换
				memcpy(&tmp_port, &udphdr->source, sizeof(tmp_port));
			    memcpy(&udphdr->source, &udphdr->dest, sizeof(tmp_port));
			    memcpy(&udphdr->dest, &tmp_port, sizeof(tmp_port));
*/

                /*-------------------- self -------------------------*/
/*
				char datagram[10240], *data, *pseudogram;

				memset(datagram, 0, 4096);

                //  eth header
				struct ethhdr *eth2 = (struct ethhdr *)datagram;

				memcpy(eth2->h_dest, eth->h_source, ETH_ALEN);
			    memcpy(eth2->h_source, eth->h_dest, ETH_ALEN);
				// memcpy(eth2->h_proto, eth->h_proto,  2); // type length  = 2
				eth2->h_proto = eth->h_proto;

				//  IP header
				struct iphdr *iph = (struct iphdr *)(datagram + sizeof(struct ethhdr));

				//  UDP header
				struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct ethhdr) + sizeof(struct ip));

				struct sockaddr_in sin;
				struct pseudo_header psh;

				data = datagram + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

				strcpy(data,  "jack");

				// sin.sin_family = AF_INET;
				// sin.sin_port = 

			    //Fill in the IP Header
			    iph->ihl = 5;
			    iph->version = 4;
			    iph->tos = 0;

				iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 5; // jack\0
				iph->id = htonl(54321);
				iph->frag_off = 0;
  				iph->ttl = 255;
				iph->protocol = IPPROTO_UDP;
				iph->check = 0;

				memcpy(&iph->saddr, &iphdr->daddr, sizeof(tmp_ip));
			    memcpy(&iph->daddr, &iphdr->saddr, sizeof(tmp_ip));

				//Ip checksum
				iph->check = csum((unsigned short *)(datagram + sizeof(struct ethhdr)), iph->tot_len);

				memcpy(&udph->source, &udphdr->source, sizeof(tmp_port));
			    memcpy(&udph->dest, &udphdr->dest, sizeof(tmp_port));

				udph->len = htons(sizeof(struct udphdr) + 5); // jack\0

				udph->check = 0;  

				//Now the UDP checksum using the pseudo header
				psh.source_address = inet_addr("10.11.1.1");
				psh.dest_address = inet_addr("10.11.1.2");
				psh.placeholder = 0;
				psh.protocol = IPPROTO_UDP;
				// psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));
				psh.udp_length = htons(sizeof(struct udphdr) + 5); // jack\0

				int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + 5; // jack\0

				pseudogram = malloc(psize);

				memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));

				memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + 5); // jack\0

				udph->check = csum((unsigned short *)pseudogram, psize);
*/

  int i, status, datalen, frame_length, sd, *ip_flags; // bytes, 
  char *interface, *target, *src_ip, *dst_ip;
  struct iphdr iphdr_assemble;
  struct udphdr udphdr_assemble;
  uint8_t *data, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Set destination MAC address: you need to fill these out
  //  ea:95:c9:55:60:64
  //   veth-adv03       
  src_mac[0] = 0xea;
  src_mac[1] = 0x95;
  src_mac[2] = 0xc9;
  src_mac[3] = 0x55;
  src_mac[4] = 0x60;
  src_mac[5] = 0x64;

  // veth0  aa:31:36:f1:7e:06
  dst_mac[0] = 0xaa;
  dst_mac[1] = 0x31;
  dst_mac[2] = 0x36;
  dst_mac[3] = 0xf1;
  dst_mac[4] = 0x7e;
  dst_mac[5] = 0x09;

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "10.11.1.1"); 
  // strcpy (src_ip, "10.0.2.15"); 

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "10.11.1.2");
  // strcpy (target, "60.205.190.117");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // UDP data
  strcpy(data, "hello-hhhh--+");

  datalen = (int)strlen(data);

  printf("\n🏀 -----datalen: %d\n\n", datalen);

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr_assemble.ihl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr_assemble.version = 4;

  // Type of service (8 bits)
  iphdr_assemble.tos = 0;

  // Total length of datagram (16 bits): IP header + UDP header + datalen
  iphdr_assemble.tot_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr_assemble.id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr_assemble.frag_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr_assemble.ttl = 255;

  // Transport layer protocol (8 bits): 17 for UDP
  iphdr_assemble.protocol = IPPROTO_UDP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr_assemble.saddr))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr_assemble.daddr))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr_assemble.check = 0;
  iphdr_assemble.check = checksum ((uint16_t *) &iphdr_assemble, IP4_HDRLEN);

  // UDP header

  // Source port number (16 bits): pick a number
  udphdr_assemble.source = htons (8080);

  // Destination port number (16 bits): pick a number
  udphdr_assemble.dest = htons (10000);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr_assemble.len = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr_assemble.check = udp4_checksum (iphdr_assemble, udphdr_assemble, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IP / 256;
  ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + UDP header + UDP data).

  // IPv4 header
  memcpy (ether_frame + ETH_HDRLEN, &iphdr_assemble, IP4_HDRLEN * sizeof (uint8_t));

  // UDP header
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr_assemble, UDP_HDRLEN * sizeof (uint8_t));

  // UDP data
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));


				uint32_t tx_idx = 0;

			    int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			    if (ret != 1) {
				    /* No more transmit slots, drop the packet */
				    return false;
			    }

			    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = (uint64_t)(ether_frame); // &ether_frame (uint64_t)
			    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = frame_length;
			    xsk_ring_prod__submit(&xsk->tx, 1);
			    xsk->outstanding_tx++;

			    xsk->stats.tx_bytes += frame_length;
			    xsk->stats.tx_packets++;

				complete_tx(xsk);


  // Free allocated memory.

  free (src_mac);
  free (dst_mac);
  free (data);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

			    return true;

			}

		}
		else
		{
			// return false;
		}
		
		


		// if (ipv4_num & 1)
		// {
		// 	// return false;
		// }
		// struct iphdr *ipv4hdr = (struct iphdr *) (eth + 1);
        // int hdrsize;
		// hdrsize = ipv4hdr->ihl * 4;
		// todo 检查三层 头部边界

    // iph->check = csum((unsigned short *)datagram, iph->tot_len);

        // ICMPv4 reply
		if(false)
		{
			int ret;
			uint32_t tx_idx = 0;
			uint8_t tmp_mac[ETH_ALEN];
			struct in_addr tmp_ip;
			struct ethhdr *eth = (struct ethhdr *)pkt;
			struct iphdr *ipv4 = (struct iphdr *) (eth + 1);
			struct icmphdr *icmp = (struct icmphdr *) (ipv4 + 1);

			if (len < (sizeof(*eth) + sizeof(*ipv4) + sizeof(*icmp)) ||
			    ipv4->protocol != IPPROTO_ICMP ||
			    icmp->type != ICMP_ECHO)
				return false;

			memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
			memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, tmp_mac, ETH_ALEN);

			memcpy(&tmp_ip, &ipv4->saddr, sizeof(tmp_ip));
			memcpy(&ipv4->saddr, &ipv4->daddr, sizeof(tmp_ip));
			memcpy(&ipv4->daddr, &tmp_ip, sizeof(tmp_ip));

			icmp->type = ICMP_ECHOREPLY;

			// csum_replace2(&icmp->checksum,
			// 	      htons(ICMP_ECHO << 8),
			// 	      htons(ICMP_ECHOREPLY << 8));

			icmp->checksum = 0;
			icmp->checksum = csum((unsigned short *)icmp, len - sizeof (struct iphdr));


			ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			if (ret != 1) {
				/* No more transmit slots, drop the packet */
				return false;
			}

			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
			xsk_ring_prod__submit(&xsk->tx, 1);
			xsk->outstanding_tx++;

			xsk->stats.tx_bytes += len;
			xsk->stats.tx_packets++;
			return true;

		}

		// return false;

	} 
	else 
	{
		// unknown
		printf("Unknown eth_type = 0x%04X \n", ip_type);
		// return false;
	}


    // ICMPv6 reply
	if (false) {
		int ret;
		uint32_t tx_idx = 0;
		uint8_t tmp_mac[ETH_ALEN];
		struct in6_addr tmp_ip;
		struct ethhdr *eth = (struct ethhdr *) pkt;
		struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
		struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

		if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
		    len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
		    ipv6->nexthdr != IPPROTO_ICMPV6 ||
		    icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
			return false;

		memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
		memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, tmp_mac, ETH_ALEN);

		memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
		memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
		memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

		icmp->icmp6_type = ICMPV6_ECHO_REPLY;

		csum_replace2(&icmp->icmp6_cksum,
			      htons(ICMPV6_ECHO_REQUEST << 8),
			      htons(ICMPV6_ECHO_REPLY << 8));

		/* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

		ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
		if (ret != 1) {
			/* No more transmit slots, drop the packet */
			return false;
		}

		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx++;

		xsk->stats.tx_bytes += len;
		xsk->stats.tx_packets++;
		return true;
	}

	return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	// complete_tx(xsk);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int ret;
	int xsks_map_fd;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
		.filename = "",
		.progsec = "xdp_sock"
	};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	struct bpf_object *bpf_obj = NULL;
	pthread_t stats_poll_thread;

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload)
	{
		printf("------cfg.do_unload");
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}
		

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {

		printf("cmdline filename = %s\n\n", cfg.filename);

		struct bpf_map *map;

		bpf_obj = load_bpf_and_xdp_attach(&cfg);
		if (!bpf_obj) {
			/* Error handling done in load_bpf_and_xdp_attach() */
			exit(EXIT_FAILURE);
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
		xsks_map_fd = bpf_map__fd(map);
		if (xsks_map_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
				strerror(xsks_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (verbose) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket);


    printf("\nbefore clean up\n");

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}




/* ------------------------------------ */ 

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum (struct iphdr iphdr_assemble, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr_assemble.saddr, sizeof (iphdr_assemble.saddr));
  ptr += sizeof (iphdr_assemble.saddr);
  chksumlen += sizeof (iphdr_assemble.saddr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr_assemble.daddr, sizeof (iphdr_assemble.daddr));
  ptr += sizeof (iphdr_assemble.daddr);
  chksumlen += sizeof (iphdr_assemble.saddr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr_assemble.protocol, sizeof (iphdr_assemble.protocol));
  ptr += sizeof (iphdr_assemble.protocol);
  chksumlen += sizeof (iphdr_assemble.protocol);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

/* ------------------------------------ */ 