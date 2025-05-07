#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>     // struct iphdr
#include <netinet/tcp.h>    // struct tcphdr
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void usage() {
    printf("syntax : netfilter-test <blocked_host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

char host_filter[256] = {0};

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, unsigned char **data)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    nfq_get_payload(tb, data);  // IP 패킷 시작 위치
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    unsigned char *pktData;
    u_int32_t id = print_pkt(nfa, &pktData);

    if (pktData != NULL) {
        struct iphdr* ip = (struct iphdr*) pktData;

        if (ip->protocol != IPPROTO_TCP)  // TCP 아니면 무시
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int ip_hdr_len = ip->ihl * 4;
        struct tcphdr* tcp = (struct tcphdr*) (pktData + ip_hdr_len);
        int tcp_hdr_len = tcp->doff * 4;

        unsigned char* http_payload = pktData + ip_hdr_len + tcp_hdr_len;
        int total_len = ntohs(ip->tot_len);
        int http_len = total_len - ip_hdr_len - tcp_hdr_len;

        if (http_len > 0 && strstr((char*)http_payload, host_filter) != NULL) {
            printf("Blocked host detected: %s\n", host_filter);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
	    usage();
	    exit(1);
    }

    snprintf(host_filter, sizeof(host_filter), "Host: %s", argv[1]);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
