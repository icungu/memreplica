#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>

static char *daddr = NULL;
static char *saddr = NULL;
static int port = 11211;

static int hide_header = 0;
static int capture_only = 0;
static int ptype = 0;

static void print_usage(char *name)
{
    printf("memreplica (memcached packet replicator)\n\n");

    printf("usage:\n   %s <interface> [options]\n\n", name);
    printf("interface:\n");
    printf("   -l ip address1     Capture packets from ip address1.\n");
    printf("   -d ip address2     Destination ip address of forwarded packets.\n");
    printf("options:\n");
    printf("   -p port            Capture packets from port.\n");
    printf("   -c                 Capture packets only.\n");
    printf("example:\n");
    printf("   sudo %s -l 192.168.0.1 -d 192.168.0.2 -p 11211\n\n'", name);
}

static void print_payload(const char *payload, int len)
{
    int i;
    const char *ch = payload;

    if (len <= 0)
        return;

    for(i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
}

static void send_packet(const char *payload, int payload_size)
{
    int s;

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) > 0)
    {
        struct sockaddr_in si_other;
        int slen = sizeof si_other;

        memset((char *) &si_other, 0, sizeof si_other);
        si_other.sin_family = AF_INET;
        si_other.sin_addr.s_addr = inet_addr(daddr);
        si_other.sin_port = htons(port);

        if (connect(s, (const struct sockaddr *)&si_other, slen) == 0)
        {
            write(s, payload, payload_size);
        }

        close(s);
    }
}

static int gethdrsize()
{
    switch (ptype)
    {
        case DLT_NULL:
            return(12);
        case DLT_EN10MB:
        case DLT_EN3MB:
            return(14);
        case DLT_LINUX_SLL:
            return(16);
        case DLT_PPP:
            return(4);
        case DLT_SLIP:
            return(16);
        case DLT_FDDI:
            return(21);
        case DLT_RAW:
            return(0);
            break;
        default:
            return(-1);
    }
}

static bool need_replica(const char *payload)
{
    const char* r_cmd[] =
        {
            "add",
            "set",
            "replace",
            "append",
            "prepend",
            "cas",
            "delete",
            NULL
        };

    int i;
    for (i = 0; r_cmd[i] != NULL; i++)
    {
        if (!strncasecmp(payload, r_cmd[i], strlen(r_cmd[i])))
        {
            return true;
        }
    }

    return false;
}

/* IP header */
struct sniff_ip
{
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp
{
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

static void got_packet(u_char *args __attribute__((unused)),
                       const struct pcap_pkthdr *header __attribute__((unused)),
                       const u_char *packet)
{
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;

    const int size_hdr = gethdrsize();
    int size_ip;
    int size_tcp;
    int size_payload;
    time_t clk = time(NULL);
    struct tm *tm = localtime(&clk);

    ip = (struct sniff_ip*)(packet + size_hdr);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20 || ip->ip_p != IPPROTO_TCP)
    {
        return;
    }

    tcp = (struct sniff_tcp*)(packet + size_hdr + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20)
    {
        return;
    }

    payload = (char *)(packet + size_hdr + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload == 0 || !need_replica(payload))
    {
        return;
    }

    if (!hide_header)
    {
        printf("[%02d/%02d/%02d %02d:%02d:%02d] %s -> ",
               tm->tm_year%100, tm->tm_mon+1, tm->tm_mday,
               tm->tm_hour, tm->tm_min, tm->tm_sec,
               inet_ntoa(ip->ip_src));
        print_payload(payload, size_payload);
    }

    if (!capture_only)
        send_packet(payload, size_payload);

    return;
}

int main(int argc, char **argv)
{

    bpf_u_int32 mask;
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_exp[128] = "";
    struct bpf_program fp;
    int c;

    /* command-line options */
    while ((c = getopt(argc, argv, "l:d:hp:c")) != EOF)
    {
        switch (c)
        {
            case 'l':
                saddr = optarg;
                break;
            case 'd':
                daddr = optarg;
                break;
            case 'h':
                hide_header = 1;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'c':
                capture_only = 1;
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (saddr == NULL || daddr == NULL)
    {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    snprintf(filter_exp, sizeof filter_exp,
             "dst host %s and dst port %d", saddr, port);

    if (pcap_lookupnet(NULL, &net, &mask, errbuf) == -1)
    {
        printf("  Error: couldn't get netmask for interface %s\n\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("\n Memcached packet replication: %s -> %s\n", saddr, daddr);
    printf("\n");

    handle = pcap_open_live(NULL, 4096, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("\n  Error: couldn't open interface: %s\n\n", errbuf);
        exit(EXIT_FAILURE);
    }

    ptype = pcap_datalink(handle);
    if (ptype == DLT_NULL)
    {
        printf("\n  Error: invalid device\n\n");
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("\n  Error: couldn't parse filter %s: %s\n\n",
               filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("\n  Error: couldn't install filter %s: %s\n\n",
               filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    exit(EXIT_SUCCESS);
}
