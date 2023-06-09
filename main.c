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

#include "libnet-headers.h"
#include "util.h"

char **host_arr;
size_t host_cnt;

static void usage(void)
{
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.csv");
}

static int load_hosts(const char *filename)
{
    FILE *fp;
    size_t _;
    char *buf = NULL;
    char *host;
    size_t n = 0x100;

    fp = fopen(filename, "r");
    if (!fp) {
        pr_err("Cannot open file: %s\n", filename);
        goto out_error;
    }

    host_arr = calloc(n, sizeof(char *));

    while (getline(&buf, &_, fp) > 0) {
        if (buf == NULL) {
            pr_err("Cannot read hosts from file\n");
            goto out_error;
        }
        
        if (host_cnt >= n) {
            n *= 2;
            host_arr = realloc(host_arr, n * sizeof(char *));
        }
        
        host = strdup(buf + strcspn(buf, ",") + 1);
        host[strcspn(host, "\n")] = '\x00';
        host_arr[host_cnt++] = host;
    }

    fclose(fp);
    free(buf);

    return 0;

out_error:
    if (fp)
        fclose(fp);
    if (host_arr)
        free(host_arr);
    if (buf)
        free(buf);

    return -1;
}

static int compare(const void *a, const void *b)
{
    /*
    * Sorting strings lexicographically using strcmp
    * https://elixir.bootlin.com/glibc/glibc-2.35/source/string/strcmp.c#L30
    */
    return strcmp(*(char **)a, *(char **)b);
}

static void sort_hosts()
{
    qsort(host_arr, host_cnt, sizeof(char *), compare);
}

static bool search_host(char *host)
{
    size_t mid;
    size_t left = 0;
    size_t right = host_cnt - 1;

    while (left <= right) {
        mid = left + (right - left) / 2;
        
        if (strcmp(host_arr[mid], host) == 0)
            return true;
        
        if (strcmp(host_arr[mid], host) < 0)
            left = mid + 1;
        else
            right = mid - 1;
    }

    return false;
}

static void unload_hosts()
{
    for (int i = 0; i < host_cnt; i++)
        free(host_arr[i]);

    free(host_arr);
    host_arr = NULL;
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
    const char *methods[] = {
        "HTTP",
        "CONNECT",
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
        "PUT",
        "TRACE",
        NULL
    };
    
    for (int i = 0; methods[i] != NULL; i++) {
        if (!strncmp(methods[i], http_data, strlen(methods[i])))
            return true;
    }
        
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

    host = host + sizeof("Host: ") -1;
    host[strcspn(host, "\r\n")] = '\x00';
    if (search_host(host) == false)
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

    sort_hosts();

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

    unload_hosts();

    exit(0);
}