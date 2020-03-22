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

#include <linux/icmp.h>

#include <netinet/udp.h>      // struct udphdr
#include <netinet/ip.h>

#include <sys/types.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"


/* --------merge header begin-------------- */
 
// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define UDP_HDRLEN  8  // UDP header length, excludes data

// Function prototypes
unsigned short int ip_csum (unsigned short int *addr, int len);

// uint16_t checksum (uint16_t *, int);
// uint16_t udp4_checksum (struct iphdr, struct udphdr, uint8_t *, int);
// char *allocate_strmem (int);
// uint8_t *allocate_ustrmem (int);
// int *allocate_intmem (int);
 
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

uint16_t parse_test_body(struct hdr_cursor *nh)
{

    // receive struct
/*
    My_UDP *my_content = (My_UDP *)(nh->pos);
    printf("\nmsg: %s", my_content->msg);
    printf("\nmsg2: %s", my_content->msg2);
    printf("\nnum: %d", (my_content->num));
    printf("\nnum: %f\n\n", (my_content->socre));
*/

    //  receive string
	char *buffer = (char *)(nh->pos);

	printf("\nContent: %s\n", (buffer));


	return strlen(buffer);
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
    sum = (sum >> 16) + (sum & 0xffff);

    sum += (sum >> 16);
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
			   uint64_t addr, uint32_t frame_len)
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

	//  get layer 3 proto type from layer 2 header
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
 
				uint16_t receive_data_len = parse_test_body(&nh); 

			    printf("\nReceive Data Len: %d\n", receive_data_len);

				char* p1 = "hello-🍄-🎲-🍎--hhh";

				uint16_t data_len = strlen(p1);

				// iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);  // ok
				iphdr->tot_len = htons (IP4_HDRLEN + UDP_HDRLEN + data_len);


				// udphdr->len = htons(ntohs(udphdr->len) - receive_data_len + data_len);  // ok
				// udphdr->len = htons(sizeof(struct udphdr) + data_len);  // ok
				udphdr->len = htons (UDP_HDRLEN + data_len);

				memcpy(nh.pos, p1, data_len); 

				printf("\n-----ReceiveFrame: %d\n", frame_len);

                // frame_len = frame_len - receive_data_len +  data_len;
                // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
                // frame_len = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDRLEN + data_len;
				frame_len =  ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + data_len;

				printf("\n-----SendFrameLen: %d\n", frame_len);


				iphdr->check = 0;
 
				iphdr->check = ip_csum((unsigned short int *)iphdr, (int)sizeof(struct iphdr));

				udphdr->check = 0;


				uint8_t tmp_mac[ETH_ALEN];
			    struct in_addr tmp_ip;
				u_int16_t tmp_port = 0;


                //  mac switch
				memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
			    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
			    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

				//  IP switch
			    memcpy(&tmp_ip, &iphdr->saddr, sizeof(tmp_ip));
			    memcpy(&iphdr->saddr, &iphdr->daddr, sizeof(tmp_ip));
			    memcpy(&iphdr->daddr, &tmp_ip, sizeof(tmp_ip));

                //  port switch
				memcpy(&tmp_port, &udphdr->source, sizeof(tmp_port));
			    memcpy(&udphdr->source, &udphdr->dest, sizeof(tmp_port));
			    memcpy(&udphdr->dest, &tmp_port, sizeof(tmp_port));

				uint32_t tx_idx = 0;

			    int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			    if (ret != 1) {
				    /* No more transmit slots, drop the packet */
				    return false;
			    }

			    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr; // &ether_frame (uint64_t)
			    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = frame_len;
			    xsk_ring_prod__submit(&xsk->tx, 1);
			    xsk->outstanding_tx++;

			    xsk->stats.tx_bytes += frame_len;
			    xsk->stats.tx_packets++;

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
		// todo check layer 3 header boundary

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

			if (frame_len < (sizeof(*eth) + sizeof(*ipv4) + sizeof(*icmp)) ||
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
			icmp->checksum = csum((unsigned short *)icmp, frame_len - sizeof (struct iphdr));


			ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			if (ret != 1) {
				/* No more transmit slots, drop the packet */
				return false;
			}

			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = frame_len;
			xsk_ring_prod__submit(&xsk->tx, 1);
			xsk->outstanding_tx++;

			xsk->stats.tx_bytes += frame_len;
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
		    frame_len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
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
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = frame_len;
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx++;

		xsk->stats.tx_bytes += frame_len;
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
	complete_tx(xsk);
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
//caculate ip checksum
unsigned short int ip_csum (unsigned short int *addr, int len)
{
	int nleft = len;
        int sum = 0;
        unsigned short int *w = addr;
	unsigned short int answer = 0; 
        while (nleft > 1) 
	{
		sum += *w++;
		nleft -= sizeof (unsigned short int);
	}
		 
	if (nleft == 1) 
	{
	 	*(char *) (&answer) = *(char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// // Computing the internet checksum (RFC 1071).
// // Note that the internet checksum does not preclude collisions.
// uint16_t
// checksum (uint16_t *addr, int len)
// {
//   int count = len;
//   register uint32_t sum = 0;
//   uint16_t answer = 0;

//   // Sum up 2-byte values until none or only one byte left.
//   while (count > 1) {
//     sum += *(addr++);
//     count -= 2;
//   }

//   // Add left-over byte, if any.
//   if (count > 0) {
//     sum += *(uint8_t *) addr;
//   }

//   // Fold 32-bit sum into 16 bits; we lose information by doing this,
//   // increasing the chances of a collision.
//   // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
//   while (sum >> 16) {
//     sum = (sum & 0xffff) + (sum >> 16);
//   }

//   // Checksum is one's compliment of sum.
//   answer = ~sum;

//   return (answer);
// }

// // Build IPv4 UDP pseudo-header and call checksum function.
// uint16_t
// udp4_checksum (struct iphdr iphdr_assemble, struct udphdr udphdr, uint8_t *payload, int payloadlen)
// {
//   char buf[IP_MAXPACKET];
//   char *ptr;
//   int chksumlen = 0;
//   int i;

//   ptr = &buf[0];  // ptr points to beginning of buffer buf

//   // Copy source IP address into buf (32 bits)
//   memcpy (ptr, &iphdr_assemble.saddr, sizeof (iphdr_assemble.saddr));
//   ptr += sizeof (iphdr_assemble.saddr);
//   chksumlen += sizeof (iphdr_assemble.saddr);

//   // Copy destination IP address into buf (32 bits)
//   memcpy (ptr, &iphdr_assemble.daddr, sizeof (iphdr_assemble.daddr));
//   ptr += sizeof (iphdr_assemble.daddr);
//   chksumlen += sizeof (iphdr_assemble.saddr);

//   // Copy zero field to buf (8 bits)
//   *ptr = 0; ptr++;
//   chksumlen += 1;

//   // Copy transport layer protocol to buf (8 bits)
//   memcpy (ptr, &iphdr_assemble.protocol, sizeof (iphdr_assemble.protocol));
//   ptr += sizeof (iphdr_assemble.protocol);
//   chksumlen += sizeof (iphdr_assemble.protocol);

//   // Copy UDP length to buf (16 bits)
//   memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
//   ptr += sizeof (udphdr.len);
//   chksumlen += sizeof (udphdr.len);

//   // Copy UDP source port to buf (16 bits)
//   memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
//   ptr += sizeof (udphdr.source);
//   chksumlen += sizeof (udphdr.source);

//   // Copy UDP destination port to buf (16 bits)
//   memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
//   ptr += sizeof (udphdr.dest);
//   chksumlen += sizeof (udphdr.dest);

//   // Copy UDP length again to buf (16 bits)
//   memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
//   ptr += sizeof (udphdr.len);
//   chksumlen += sizeof (udphdr.len);

//   // Copy UDP checksum to buf (16 bits)
//   // Zero, since we don't know it yet
//   *ptr = 0; ptr++;
//   *ptr = 0; ptr++;
//   chksumlen += 2;

//   // Copy payload to buf
//   memcpy (ptr, payload, payloadlen);
//   ptr += payloadlen;
//   chksumlen += payloadlen;

//   // Pad to the next 16-bit boundary
//   for (i=0; i<payloadlen%2; i++, ptr++) {
//     *ptr = 0;
//     ptr++;
//     chksumlen++;
//   }

//   return checksum ((uint16_t *) buf, chksumlen);
// }

// // Allocate memory for an array of chars.
// char *
// allocate_strmem (int len)
// {
//   void *tmp;

//   if (len <= 0) {
//     fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
//     exit (EXIT_FAILURE);
//   }

//   tmp = (char *) malloc (len * sizeof (char));
//   if (tmp != NULL) {
//     memset (tmp, 0, len * sizeof (char));
//     return (tmp);
//   } else {
//     fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
//     exit (EXIT_FAILURE);
//   }
// }

// // Allocate memory for an array of unsigned chars.
// uint8_t *
// allocate_ustrmem (int len)
// {
//   void *tmp;

//   if (len <= 0) {
//     fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
//     exit (EXIT_FAILURE);
//   }

//   tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
//   if (tmp != NULL) {
//     memset (tmp, 0, len * sizeof (uint8_t));
//     return (tmp);
//   } else {
//     fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
//     exit (EXIT_FAILURE);
//   }
// }

// // Allocate memory for an array of ints.
// int *
// allocate_intmem (int len)
// {
//   void *tmp;

//   if (len <= 0) {
//     fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
//     exit (EXIT_FAILURE);
//   }

//   tmp = (int *) malloc (len * sizeof (int));
//   if (tmp != NULL) {
//     memset (tmp, 0, len * sizeof (int));
//     return (tmp);
//   } else {
//     fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
//     exit (EXIT_FAILURE);
//   }
// }

/* ------------------------------------ */ 