#include <stdint.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define RX_RING_SIZE 128        //接收环大小
#define TX_RING_SIZE 128        //发送环大小

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static char Message[] =
{
	0x02,0x01,0x07,0x00,0x78,0x00,0x00,0x31,0x30,0x30,0x30,0x31,0x1f,0x30,0x1f,
	0x30,0x30,0x1f,0x32,0x30,0x30,0x30,0x2d,0x30,0x31,0x2d,0x30,0x31,0x1f,0x30,
	0x30,0x3a,0x30,0x30,0x3a,0x30,0x30,0x1f,0x68,0x65,0x6c,0x6c,0x6f,0x21,0x03
};

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
* Initializes a given port using global settings and with the RX buffers
* coming from the mbuf_pool passed as a parameter.
*/

static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;      //网口配置=默认的网口配置
	const uint16_t rx_rings = 1, tx_rings = 1;              //网口tx、rx队列的个数
	int retval;                     //临时变量，返回值
	uint16_t q;                     //临时变量，队列号

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);   //设置网卡设备
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	//RX队列初始化
	for (q = 0; q < rx_rings; q++) {        //遍历指定网口的所有rx队列
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
			rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	//TX队列初始化
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {        //遍历指定网口的所有tx队列
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,  
			rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);       //启动网卡
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);       //获取网卡的MAC地址，并打印
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		(unsigned)port,
		addr.addr_bytes[0], addr.addr_bytes[1],
		addr.addr_bytes[2], addr.addr_bytes[3],
		addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);       //设置网卡为混杂模式

	return 0;
}

/*
* The lcore main. This is the main thread that does the work, reading from
* an input port and writing to an output port.
*/

static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();   //网口总数
	uint8_t port;                                   //临时变量，网口号

													/*
													* Check that the port is on the same NUMA node as the polling thread
													* for best performance.
													*/
	for (port = 0; port < nb_ports; port++)                 //遍历所有网口
		if (rte_eth_dev_socket_id(port) > 0 &&          //检测的IF语句
			rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		rte_lcore_id());

	struct ether_hdr etHdr;
	struct ipv4_hdr ipHdr;
	struct udp_hdr udpHdr;
	struct rte_mbuf *bufs[BURST_SIZE];
	const uint16_t iTotalSize,iUdpSize;
	const uint8_t iIPVersion,iIPSize;

	rte_eth_macaddr_get(port, &etHdr->s_addr);
	rte_eth_macaddr_get(port^1, &etHdr->d_addr);
	ethdr->ether_type = rte_be_to_cpu_16(ETHER_TYPE_IPV4);

	iTotalSize = sizeof(ipHdr) + sizeof(udpHdr) + sizeof(Message);

	iIPVersion = 4;
	iIPSize = sizeof(ipHdr) / sizeof(uint8_t);

	ipHdr->version_ihl = (iIPVersion << 4) | iIPSize;//这里感觉也有点问题，可以这样写吗？
	ipHdr->type_of_service = 0;
	ipHdr->total_length = htons(iTotalSize);
	ipHdr->packet_id = 0;
	ipHdr->fragment_offset = 0;
	ipHdr->time_to_live = 128;
	ipHdr->next_proto_id = 17;
	ipHdr->hdr_checksum = 0;
	ipHdr->src_addr = inet_addr(GetLocalIpAddr());//上面这几个在DPDK中提供了可调用的接口吗？
	ipHdr->dst_addr = ipHdr.src_addr

	iUdpSize = sizeof(udpHdr) + sizeof(Message);

	udpHdr->src_port = 0；//从哪获取端口号？
	udpHdr->dst_port = udpHdr->src_port;
	udpHdr->dgram_len = htons(iUdpSize);
	udpHdr->dgram_cksum = 0;

	memcpy(bufs, &etHdr, sizeof(etHdr));
	memcpy(bufs + sizeof(etHdr), &ipHdr, sizeof(ipHdr));
	memcpy(bufs + sizeof(etHdr) + sizeof(ipHdr), &udpHdr, sizeof(udpHdr));
	memcpy(bufs + sizeof(etHdr)+iTotalSize, &Message, sizeof(Message));

	/* Run until the application is quit or killed. */
	/*运行 直到 应用程序 推出 或 被kill*/
	for (;;) {
		/*
		* Receive packets on a port and forward them on the paired
		* port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		*/
		for (port = 0; port < nb_ports; port++) {       //遍历所有网口
			/* Send burst of TX packets, to second port of pair. */
			//发包，发送nb_rx个包
			//端口，队列，发送缓冲区，发包个数
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
				bufs, nb_rx);

			/* Free any unsent packets. */
			//if (unlikely(nb_tx < nb_rx)) {
				//uint16_t buf;
				//for (buf = nb_tx; buf < nb_rx; buf++)
					//rte_pktmbuf_free(bufs[buf]);    //释放包
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
	struct rte_mempool *mbuf_pool;  //指向内存池结构的指针变量
	unsigned nb_ports;              //网口个数
	uint8_t portid;                 //网口号，临时的标记变量

									/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);     //初始化
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

									/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count(); //获取当前有效网口的个数
	if (nb_ports < 2 || (nb_ports & 1))     //如果有效网口数小于2或有效网口数为奇数0，则出错
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	//初始化所有的网口
	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)   //遍历所有网口
		if (port_init(portid, mbuf_pool) != 0)  //初始化指定网口，需要网口号和内存池，此函数为自定义函数，看前面定义
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
				portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	//执行主函数
	lcore_main();

	return 0;
}