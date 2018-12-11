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

#define RX_RING_SIZE 128        //���ջ���С
#define TX_RING_SIZE 128        //���ͻ���С

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 2000

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
	struct rte_eth_conf port_conf = port_conf_default;      //��������=Ĭ�ϵ���������
	const uint16_t rx_rings = 1, tx_rings = 1;              //����tx��rx���еĸ���
	int retval;                     //��ʱ����������ֵ
	uint16_t q;                     //��ʱ���������к�

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);   //���������豸
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	//RX���г�ʼ��
	for (q = 0; q < rx_rings; q++) {        //����ָ�����ڵ�����rx����
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
			rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	//TX���г�ʼ��
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {        //����ָ�����ڵ�����tx����
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
			rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);       //��������
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);       //��ȡ������MAC��ַ������ӡ
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		(unsigned)port,
		addr.addr_bytes[0], addr.addr_bytes[1],
		addr.addr_bytes[2], addr.addr_bytes[3],
		addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);       //��������Ϊ����ģʽ

	return 0;
}

/*
* The lcore main. This is the main thread that does the work, reading from
* an input port and writing to an output port.
*/

static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();   //��������
	uint8_t port;                                   //��ʱ���������ں�

													/*
													* Check that the port is on the same NUMA node as the polling thread
													* for best performance.
													*/
	for (port = 0; port < nb_ports; port++)                 //������������
		if (rte_eth_dev_socket_id(port) > 0 &&          //����IF���
			rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		rte_lcore_id());

	char Receive[45];
	struct ether_hdr etHdr;
	struct ipv4_hdr ipHdr;
	struct udp_hdr udpHdr;

	/* Run until the application is quit or killed. */
	/*���� ֱ�� Ӧ�ó��� �Ƴ� �� ��kill*/
	for (;;){
		port=1;
														/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];

			//�հ������յ�nb_tx����
			//�˿ڣ����У��հ����У����д�С
			const uint16_t nb_rx = rte_eth_rx_burst(1, 0,
				bufs, BURST_SIZE);

			memcpy(&Receive[45],bufs+sizeof(etHdr)+sizeof(ipHdr)+sizeof(udpHdr),sizeof(Message));
			if(strcmp(Receive,Message)==0)
				printf("Pass");
			else printf("Error");

			rte_pktmbuf_free(bufs[1]);

	}
}

/*
* The main function, which does initialization and calls the per-lcore
* functions.
*/
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;  //ָ���ڴ�ؽṹ��ָ�����
	unsigned nb_ports;              //���ڸ���
	uint8_t portid;                 //���ںţ���ʱ�ı�Ǳ���

									/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);     //��ʼ��
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count(); //��ȡ��ǰ��Ч���ڵĸ���
	if (nb_ports < 2 || (nb_ports & 1))     //�����Ч������С��2����Ч������Ϊ����0�������
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	//��ʼ�����е�����
	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)   //������������
		if (port_init(portid, mbuf_pool) != 0)  //��ʼ��ָ�����ڣ���Ҫ���ںź��ڴ�أ��˺���Ϊ�Զ��庯������ǰ�涨��
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
				portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	//ִ��������
	lcore_main();

	return 0;
}