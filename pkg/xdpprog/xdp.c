// +build ignore

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct packet {
    // Protocol
    __be16 l3_proto;
    __be16 l4_proto;

    union {
        // IPv4
        struct {
            __be32 saddr;
            __be32 daddr;
        };

        // IPv6
        struct {
            struct in6_addr saddr6;
            struct in6_addr daddr6;
        };
    };

    // TCP/UDP
    __be16 sport;
    __be16 dport;
};

typedef enum {
    OK,
    INVALID_DATA_LENGTH,
    INVALID_PROTO,
    INVALID_IP,
} stauts_t;

static stauts_t make_packet_icmp(struct packet *pkt, void *data,
                                 void *data_end);
static stauts_t make_packet_udp(struct packet *pkt, void *data, void *data_end);
static stauts_t make_packet_tcp(struct packet *pkt, void *data, void *data_end);
static stauts_t make_packet_ipv4(struct packet *pkt, void *data,
                                 void *data_end);
static stauts_t make_packet_ipv6(struct packet *pkt, void *data,
                                 void *data_end);
static stauts_t make_packet(struct packet *pkt, void *data, void *data_end);
static stauts_t is_valid_ip(struct packet *pkt);

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} xsk_map SEC(".maps");

// IP
struct ip_lpm_key {
    __u32 prefix_len;
    __u8 data[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ip_lpm_key);
    __type(value, __u8);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_lpm_trie SEC(".maps");

SEC("xdp")
int xdp_redirect_xsk_prog(struct xdp_md *ctx)
{
    void *data = (void *)(__s64)ctx->data;
    void *data_end = (void *)(__s64)ctx->data_end;

    // Make packet
    struct packet pkt = {};
    if (make_packet(&pkt, data, data_end) != OK)
        return XDP_PASS;

    // Check ip valid
    if (is_valid_ip(&pkt) != OK)
        return XDP_DROP;

    // Redirect
    int index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsk_map, &index))
        return bpf_redirect_map(&xsk_map, index, XDP_PASS);
    return XDP_PASS;
}

typedef enum { WHITELIST, BLOCKLIST } firewall_mode_t;

firewall_mode_t firewall_mode = WHITELIST;

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data = (void *)(__s64)ctx->data;
    void *data_end = (void *)(__s64)ctx->data_end;

    // Make packet
    struct packet pkt = {};
    if (make_packet(&pkt, data, data_end) != OK)
        return XDP_PASS;

    // Check ip valid
    if (firewall_mode == WHITELIST)
        return is_valid_ip(&pkt) == OK ? XDP_PASS : XDP_DROP;
    return is_valid_ip(&pkt) == OK ? XDP_DROP : XDP_PASS;
}

static inline stauts_t is_valid_ip(struct packet *pkt)
{
    // Filter
    struct ip_lpm_key key = {};
    switch (pkt->l3_proto) {
    case ETH_P_IP:
        key.prefix_len = 32;
        __builtin_memcpy(key.data, &(pkt->saddr), sizeof(pkt->saddr));
        break;
    case ETH_P_IPV6:
        key.prefix_len = 128;
        __builtin_memcpy(key.data, &(pkt->saddr6), sizeof(pkt->saddr6));
        break;
    default:
        return INVALID_PROTO;
    }
    return bpf_map_lookup_elem(&ip_lpm_trie, &key) ? OK : INVALID_IP;
}

static stauts_t make_packet(struct packet *pkt, void *data, void *data_end)
{
    // L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return OK;

    __be16 eth_type = bpf_ntohs(eth->h_proto);
    __be16 off = sizeof(*eth);

    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return INVALID_DATA_LENGTH;

        eth_type = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        off += sizeof(*vlan);
    }

    switch (eth_type) {
    case ETH_P_IP:
        return make_packet_ipv4(pkt, data + off, data_end);
    case ETH_P_IPV6:
        return make_packet_ipv6(pkt, data + off, data_end);
    default:
        return INVALID_PROTO;
    }
}

static stauts_t make_packet_ipv4(struct packet *pkt, void *data, void *data_end)
{
    struct iphdr *ip = (struct iphdr *)data;
    if ((void *)(ip + 1) > data_end)
        return INVALID_DATA_LENGTH;

    pkt->l3_proto = ETH_P_IP;
    pkt->saddr = ip->saddr;
    pkt->daddr = ip->daddr;

    __u16 off = ip->ihl * 4;
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        return make_packet_icmp(pkt, data + off, data_end);
    case IPPROTO_UDP:
        return make_packet_udp(pkt, data + off, data_end);
    case IPPROTO_TCP:
        return make_packet_tcp(pkt, data + off, data_end);
    default:
        return INVALID_PROTO;
    }
}

static stauts_t make_packet_ipv6(struct packet *pkt, void *data, void *data_end)
{
    struct ipv6hdr *ip = (struct ipv6hdr *)data;
    if ((void *)(ip + 1) > data_end)
        return INVALID_DATA_LENGTH;

    pkt->l3_proto = ETH_P_IPV6;
    pkt->saddr6 = ip->saddr;
    pkt->daddr6 = ip->daddr;

    __u16 off = sizeof(*ip);
    switch (ip->nexthdr) {
    case IPPROTO_ICMP:
        return make_packet_icmp(pkt, data + off, data_end);
    case IPPROTO_UDP:
        return make_packet_udp(pkt, data + off, data_end);
    case IPPROTO_TCP:
        return make_packet_tcp(pkt, data + off, data_end);
    default:
        return INVALID_PROTO;
    }
}

static stauts_t make_packet_icmp(struct packet *pkt, void *data, void *data_end)
{
    struct icmphdr *icmp = (struct icmphdr *)data;
    if ((void *)(icmp + 1) > data_end)
        return INVALID_DATA_LENGTH;

    pkt->l4_proto = IPPROTO_ICMP;
    pkt->sport = 0;
    pkt->dport = 0;

    return OK;
}

static stauts_t make_packet_udp(struct packet *pkt, void *data, void *data_end)
{
    struct udphdr *udp = (struct udphdr *)data;
    if ((void *)(udp + 1) > data_end)
        return INVALID_DATA_LENGTH;

    pkt->l4_proto = IPPROTO_UDP;
    pkt->sport = bpf_ntohs(udp->source);
    pkt->dport = bpf_ntohs(udp->dest);

    return OK;
}

static stauts_t make_packet_tcp(struct packet *pkt, void *data, void *data_end)
{
    struct tcphdr *tcp = (struct tcphdr *)data;
    if ((void *)(tcp + 1) > data_end)
        return INVALID_DATA_LENGTH;

    pkt->l4_proto = IPPROTO_TCP;
    pkt->sport = bpf_ntohs(tcp->source);
    pkt->dport = bpf_ntohs(tcp->dest);

    return OK;
}

char _license[] SEC("license") = "GPL";
