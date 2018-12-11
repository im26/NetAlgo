#include <rte_config.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#include <rte_errno.h>


#define IP_VERSION 0x04
#define IP_HDRLEN  0x05 /*5字节的头*/
#define IP_DEFTTL  128
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define IP_DN_FRAGMENT_FLAG 0x0040

#define RX_RING_SIZE 64
#define TX_RING_SIZE 64

#define NUM_MBUFS 512
#define MBUF_CACHE_SIZE 32
#define BURST_SIZE 32

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1


struct ether_addr addr[2];

static const struct rte_eth_conf port_conf_default = {
        .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN}
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)  //初始化网口设置
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;

    if (port >= rte_eth_dev_count())
        return -1;

    /* 配置以太网设备 */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    /* 为每个以太网端口设置与配置一个 rx（进流量）队列  */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* 为每个以太网端口设置与配置一个 tx（出流量）队列 */
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    /* 打开以太网端口. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* 显示端口mac地址. */
    rte_eth_macaddr_get(port, &addr[port]);
    printf("Port %u MAC: %02x %02x %02x %02x %02x %02x\n",
           (unsigned)port,
           addr[port].addr_bytes[0], addr[port].addr_bytes[1],
           addr[port].addr_bytes[2], addr[port].addr_bytes[3],
           addr[port].addr_bytes[4], addr[port].addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

static char *
getPacketInfo(struct rte_mbuf * m){
    struct ether_hdr *ether_header = rte_pktmbuf_mtod(m,struct ether_hdr*);
    struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *) &ether_header[1];
    struct udp_hdr *udp_header = (struct udp_hdr *) &ipv4_header[1];
    char *actual_content = (char *) &udp_header[1];
    char * string = (char*)malloc(2048 * sizeof(char));

    struct ether_addr ether_d_addr = ether_header->d_addr,ether_s_addr = ether_header->s_addr;
    uint8_t * ip_src = (uint8_t*)(&ipv4_header->src_addr), * ip_dst = (uint8_t*)(&ipv4_header->dst_addr);

    snprintf(string,2048,"eth.dst=%02x %02x %02x %02x %02x %02x\n"
                     "eth.src=%02x %02x %02x %02x %02x %02x\n"
                     "ip.dst=%u.%u.%u.%u,ip.src=%u.%u.%u.%u\n"
                     "udp.src_port=%u,udp.dst_port=%u\n"
                     "udp_datagram=%s\n",
             ether_d_addr.addr_bytes[0], ether_d_addr.addr_bytes[1], ether_d_addr.addr_bytes[2], ether_d_addr.addr_bytes[3], ether_d_addr.addr_bytes[4], ether_d_addr.addr_bytes[5],
             ether_s_addr.addr_bytes[0], ether_s_addr.addr_bytes[1], ether_s_addr.addr_bytes[2], ether_s_addr.addr_bytes[3], ether_s_addr.addr_bytes[4], ether_s_addr.addr_bytes[5],
             ip_src[0], ip_src[1], ip_src[2], ip_src[3],
             ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3],
             udp_header->src_port,udp_header->dst_port,
             actual_content
    );

    return string;
}
//构建一个网络包
static struct rte_mbuf *
createUDP(struct rte_mempool *mp, uint8_t port_id){
    char content[]="This is a UDP packet!"; //包内容

    struct rte_mbuf *udp_pkt = rte_pktmbuf_alloc(mp);
    udp_pkt->ol_flags |= PKT_TX_UDP_CKSUM | PKT_TX_IPV4 | PKT_TX_IP_CKSUM ;

    struct ether_hdr *ether_header = (struct ether_hdr *) rte_pktmbuf_prepend(udp_pkt,sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + sizeof(content));
    struct ipv4_hdr *ipv4_header = (struct ipv4_hdr *) &ether_header[1];
    struct udp_hdr *udp_header = (struct udp_hdr *) &ipv4_header[1];
    char *actual_content = (char *) &udp_header[1];

    rte_memcpy(&ether_header->s_addr,&addr[0],sizeof(struct ether_addr));
    rte_memcpy(&ether_header->d_addr,&addr[1],sizeof(struct ether_addr));
    ether_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_header->version_ihl = IP_VHL_DEF;
    ipv4_header->type_of_service = 0;
    ipv4_header->total_length = rte_cpu_to_be_16(udp_pkt->data_len - sizeof(struct ether_hdr));
    ipv4_header->packet_id = 0;
    ipv4_header->fragment_offset = IP_DN_FRAGMENT_FLAG;
    ipv4_header->time_to_live = IP_DEFTTL;
    ipv4_header->next_proto_id = IPPROTO_UDP;
    ipv4_header->hdr_checksum = 0;
    ipv4_header->src_addr = rte_cpu_to_be_16(IPv4(192,168,1,5));
    ipv4_header->dst_addr = rte_cpu_to_be_16(IPv4(192,168,1,2));

    udp_header->dgram_cksum = 0;
    udp_header->dgram_len = sizeof(content);
    udp_header->src_port = rte_cpu_to_be_16((uint16_t)9999);
    udp_header->dst_port = rte_cpu_to_be_16((uint16_t)8888);

    for(int i=0;i<sizeof(content);i++){
        actual_content[i] = content[i];
    }

    udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_header,udp_header);
    ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);

    return udp_pkt;

}



/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(struct rte_mempool *mbuf_pool)
{
    static unsigned sent_udp = 0;
    const uint8_t nb_ports = rte_eth_dev_count();
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    for (uint8_t port = 0; port < nb_ports; port++)
        if (rte_eth_dev_socket_id(port) > 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to polling thread.\n\tPerformance will not be optimal.\n", port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    /* Run until the application is quit or killed. */
    while (sent_udp < 100) {
        {
            uint8_t port = 0;
            struct rte_mbuf * constructed_udp_pkt = createUDP(mbuf_pool, port);
            uint16_t nb_tx = rte_eth_tx_burst(port,0,&constructed_udp_pkt,1);
            if(nb_tx == 1) printf("sent the %uth udp packet at port %u\n",++sent_udp,port);
            rte_pktmbuf_free(constructed_udp_pkt);
        }
        {
            uint8_t port = 1;
            /* Get burst of RX packets, from first port of pair. */
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
            if (nb_rx != 0){
                printf("Receive %u packet from port %u\n",nb_rx,port);
                for(uint i=0;i<nb_rx;i++){
                    char * packet_string = getPacketInfo(bufs[i]);
                    printf("%s\n",packet_string);
                    free(packet_string);
                }
            }
        }
    }

}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check that there is an even number of ports to send/receive on. */
    unsigned nb_ports = rte_eth_dev_count();
    if (nb_ports != 2)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be 2, one for transmitting a udp packet, another for receiving that\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    for (uint8_t port_id = 0; port_id < nb_ports; port_id++)
        if (port_init(port_id, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port_id);

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    /* Call lcore_main on the master core only. */
    lcore_main(mbuf_pool);

    return 0;
}
