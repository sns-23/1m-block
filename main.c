#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <glib.h>

#include "libnet-headers.h"
#include "util.h"

GArray *host_arr;

static void usage(void)
{
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net");
}

static uint32_t get_pkt_id(struct nfq_data *nfa)
{
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) 
        return -1;

    return ntohl(ph->packet_id);
}

static bool check_http(char *http_data)
{
    /* 
    * HTTP header starts with method name or "HTTP" 
    * https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods 
    */
    if (strcmp(http_data, "HTTP"))
        return true;

    if (strcmp(http_data, "CONNECT"))
        return true;

    if (strcmp(http_data, "DELETE"))
        return true;

    if (strcmp(http_data, "GET"))
        return true;

    if (strcmp(http_data, "HEAD"))
        return true;

    if (strcmp(http_data, "OPTIONS"))
        return true;

    if (strcmp(http_data, "POST"))
        return true;

    if (strcmp(http_data, "PUT"))
        return true;
    
    if (strcmp(http_data, "TRACE"))
        return true;
    
    return false;
}

static int check_host(struct nfq_data* nfa)
{
    struct nfqnl_msg_packet_hdr *ph;
    struct libnet_ipv4_hdr *ipv4_hdr;
    struct libnet_tcp_hdr *tcp_hdr;
    unsigned char *data;
    char *http_hdr;
    char *host;
    int http_data_len;
    int data_len;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        fprintf(stderr, "Cannot get packet header\n");
        return NF_ACCEPT;
    }

    if (ntohs(ph->hw_protocol) != ETHER_TYPE_IPV4)
        return NF_ACCEPT;

    data_len = nfq_get_payload(nfa, &data);
    if (data_len < 0) {
        fprintf(stderr, "Cannot get payload\n");
        return NF_ACCEPT;
    }

    ipv4_hdr = data;
    if (ipv4_hdr->ip_p != IPV4_PROTOCOL_TCP)
        return NF_ACCEPT;
    
    tcp_hdr = (char *)ipv4_hdr + ipv4_hdr->ip_hl * 4;

    http_hdr = (char *)tcp_hdr + tcp_hdr->th_off * 4;
    http_data_len = ntohs(ipv4_hdr->ip_len) - ipv4_hdr->ip_hl * 4 - tcp_hdr->th_off * 4;
    http_hdr[http_data_len] = 0;

    /* 
    * minimun length of http request is always greater than 16 bytes
    * http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes 
    */
    if (http_data_len < 16)
        return NF_ACCEPT;

    if (!check_http(http_hdr))
        return NF_ACCEPT;
    
    host = strstr(http_hdr, "Host: ");
    if (host == NULL)
        return NF_ACCEPT;

    if (g_array_binary_search(host_arr, host, g_strcmp0, NULL) == false)
        return NF_ACCEPT;

    return NF_DROP;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    uint32_t id;
    int verdict;
    
    id = get_pkt_id(nfa);

    if (id == (uint32_t)-1) {
        fprintf(stderr, "Cannot get packet id\n");
        return -1;
    }

    verdict = check_host(nfa);

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int g_arr_init(void)
{
    host_arr = g_array_new(false, false, sizeof(char *));
    if (!host_arr)
        return -1;
    return 0;
}

void g_arr_destroy(void)
{
    if (host_arr) {
        g_array_free(host_arr, true);
        host_arr = NULL;
    }
}

int load_hosts(const char *filename)
{
    FILE *fp;
    size_t n;
    char *buf = NULL;
    char *host;

    fp = fopen(filename, "r");
    if (!fp) {
        pr_err("Cannot open file: %s\n", filename);
        goto out_error;
    }

    if (g_arr_init() < 0) {
        pr_err("Cannot create hash table\n");
        goto out_error;
    }

    while (getline(&buf, &n, fp) > 0) {
        if (buf == NULL) {
            pr_err("Cannot read hosts from file\n");
            goto out_error;
        }
        
        host = strdup(buf + strcspn(buf, ",") + 1);
        g_array_append_vals(host_arr, &host, 1);
    }

    fclose(fp);
    free(buf);

    return 0;

out_error:
    if (fp)
        fclose(fp);
    if (buf)
        free(buf);
    g_arr_destroy();
    return -1;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        usage();
        return 1;
    }

    if (load_hosts(argv[1]) < 0)
        return 1;

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    g_arr_destroy();

    exit(0);
}