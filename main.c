#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <time.h>

#include <sloop/avl.h>
#include <sloop/loop.h>

static void now(struct timespec *t) {
	clock_gettime(CLOCK_MONOTONIC, t);
}

static int ms_since(struct timespec *t) {
	struct timespec n;
	if (t->tv_sec == 0) return -1;
	now(&n);
	return (n.tv_sec - t->tv_sec) * 1000 + (n.tv_nsec - t->tv_nsec) / 1000000;
}

struct tcp_connection {
	struct endpoint {
		uint32_t ip;
		uint16_t port;
	} src, dst;
	enum {
		TCP_STATE_INIT = 0,
		TCP_STATE_CONNECTED,
		TCP_STATE_CLOSED,
		TCP_STATE_REJECTED,
	} state;
	struct timespec last_activity;
	struct timespec time_discovered;
	struct timespec time_connected;
	struct timespec time_disconnected;

	int fin_c_to_s; // client to server direction is shutdown
	int fin_s_to_c; // server to client direction is shutdown

	struct avl_node tcp_connections;
};

// Deterministically swap e1 and e2 to do pairs matching
static void sort_endpoints(struct endpoint **e1, struct endpoint **e2) {
	if ((*e1)->ip > (*e2)->ip || ((*e1)->ip == (*e2)->ip && (*e1)->port > (*e2)->port)) {
		struct endpoint *t = *e2;
		*e2 = *e1;
		*e1 = t;
	}
}

static int tcp_connection_comp(const void *k1, const void *k2, void *ptr) {
	struct tcp_connection *c1 = (struct tcp_connection *)k1, *c2 = (struct tcp_connection *)k2;
	struct endpoint *c1_1 = &c1->src;
	struct endpoint *c1_2 = &c1->dst;
	struct endpoint *c2_1 = &c2->src;
	struct endpoint *c2_2 = &c2->dst;
	uint32_t v;

	// swap endpoints as necessary to compare deterministically
	sort_endpoints(&c1_1, &c1_2);
	sort_endpoints(&c2_1, &c2_2);

	v = c1_1->ip - c2_1->ip;
	if (v) return v;
	v = c1_2->ip - c2_2->ip;
	if (v) return v;
	v = c1_1->port - c2_1->port;
	if (v) return v;
	v = c1_2->port - c2_2->port;
	if (v) return v;

	return 0;
}

AVL_TREE(tcp_connections, &tcp_connection_comp, /* no dups */ 0, NULL);

static int bind_socket(int ifindex) {
	int fd = -1;
	int rc;
	struct sockaddr_ll sockaddr = { 0 };

	// ETH_P_IP would be just what we want, except that it implicitely disables egress packets...
	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL) /*htons(ETH_P_IP)*/);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_ifindex = ifindex;

	rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (rc < 0) {
		perror("bind");
		goto error;
	}
/*
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	rc = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (rc < 0) {
		perror("setsockopt");
		goto error;
	}
*/
	return fd;
error:
	if (rc >= 0)
		close(rc);
	return -1;
}

union {
	struct iphdr ip;
	char buffer[1600];
} packet;

struct packet_info {
	struct endpoint src, dst;
	enum {
		PKT_PROTO_TCP,
		PKT_PROTO_UDP,
		PKT_PROTO_OTHER,
	} type;
	union {
		struct {
			enum {
				TCP_FLAG_SYN = 1 << 0,
				TCP_FLAG_ACK = 1 << 1,
				TCP_FLAG_FIN = 1 << 2,
				TCP_FLAG_RST = 1 << 3,
			} flags;
			uint32_t seq;
			uint32_t ack;
		} tcp;
	};
};

static void packet_dissect(struct packet_info *packet_info) {
	packet_info->type = PKT_PROTO_OTHER;
	packet_info->src.ip = packet.ip.saddr;
	packet_info->dst.ip = packet.ip.daddr;

	switch (packet.ip.protocol) {
		case IPPROTO_TCP:
			{
				struct tcphdr *tcphdr;

				packet_info->type = PKT_PROTO_TCP;
				tcphdr = (struct tcphdr *)(((uint32_t *)&packet) + packet.ip.ihl);
				packet_info->src.port = ntohs(tcphdr->source);
				packet_info->dst.port = ntohs(tcphdr->dest);

				packet_info->tcp.flags = 0;

				if (tcphdr->syn)
					packet_info->tcp.flags |= TCP_FLAG_SYN;
				if (tcphdr->ack)
					packet_info->tcp.flags |= TCP_FLAG_ACK;
				if (tcphdr->fin)
					packet_info->tcp.flags |= TCP_FLAG_FIN;
				if (tcphdr->rst)
					packet_info->tcp.flags |= TCP_FLAG_RST;

				packet_info->tcp.seq = ntohs(tcphdr->seq);
				packet_info->tcp.ack = ntohs(tcphdr->ack);
			}
			break;
		case IPPROTO_UDP:
			{
				struct udphdr *udphdr;

				packet_info->type = PKT_PROTO_UDP;
				udphdr = (struct udphdr *)(((uint32_t *)&packet) + packet.ip.ihl);
				packet_info->src.port = ntohs(udphdr->source);
				packet_info->dst.port = ntohs(udphdr->dest);
			}
			break;
		default:
			break;
	}

}

static void packet_print(struct packet_info *packet_info) {
	const char *proto;
	switch (packet_info->type) {
		case PKT_PROTO_TCP:
			proto = "TCP";
			break;
		case PKT_PROTO_UDP:
			proto = "UDP";
			break;
		case PKT_PROTO_OTHER:
		default:
			proto = "???";
			break;
	}
	printf("[%s] %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d ",
			proto,
			(int)((unsigned char *)&(packet_info->src.ip))[0],
			(int)((unsigned char *)&(packet_info->src.ip))[1],
			(int)((unsigned char *)&(packet_info->src.ip))[2],
			(int)((unsigned char *)&(packet_info->src.ip))[3],
			(int)packet_info->src.port,
			(int)((unsigned char *)&(packet_info->dst.ip))[0],
			(int)((unsigned char *)&(packet_info->dst.ip))[1],
			(int)((unsigned char *)&(packet_info->dst.ip))[2],
			(int)((unsigned char *)&(packet_info->dst.ip))[3],
			(int)packet_info->dst.port
	      );
	if (packet_info->type == PKT_PROTO_TCP) {
		if (packet_info->tcp.flags & TCP_FLAG_SYN)
			putchar('S');
		if (packet_info->tcp.flags & TCP_FLAG_ACK)
			putchar('A');
		if (packet_info->tcp.flags & TCP_FLAG_FIN)
			putchar('F');
		if (packet_info->tcp.flags & TCP_FLAG_RST)
			putchar('R');
	}
	putchar('\n');
}

static void tcp_connection_print(struct tcp_connection *conn) {
	const char *state;
	switch (conn->state) {
		case TCP_STATE_INIT: state = "init"; break;
		case TCP_STATE_REJECTED: state = "rejected"; break;
		case TCP_STATE_CONNECTED: state = "connected"; break;
		case TCP_STATE_CLOSED: state = "closed"; break;
	}
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d \t%s discovered:%dms connected:%dms closed:%dms activity:%dms\n",
			(int)((unsigned char *)&(conn->src.ip))[0],
			(int)((unsigned char *)&(conn->src.ip))[1],
			(int)((unsigned char *)&(conn->src.ip))[2],
			(int)((unsigned char *)&(conn->src.ip))[3],
			(int)conn->src.port,
			(int)((unsigned char *)&(conn->dst.ip))[0],
			(int)((unsigned char *)&(conn->dst.ip))[1],
			(int)((unsigned char *)&(conn->dst.ip))[2],
			(int)((unsigned char *)&(conn->dst.ip))[3],
			(int)conn->dst.port,
			state,
			ms_since(&conn->time_discovered),
			ms_since(&conn->time_connected),
			ms_since(&conn->time_disconnected),
			ms_since(&conn->last_activity));
}

static struct tcp_connection* tcp_connection_find(struct packet_info *info) {
	struct tcp_connection conn;

	conn.src = info->src;
	conn.dst = info->dst;

	return avl_find_element(&tcp_connections, &conn, &conn, tcp_connections);
}

static struct tcp_connection *tcp_connection_new(struct packet_info *info) {
	struct tcp_connection *conn;

	conn = (struct tcp_connection *)malloc(sizeof(*conn));
	memset(conn, 0, sizeof(*conn));
	conn->src = info->src;
	conn->dst = info->dst;

	conn->tcp_connections.key = conn;

	return conn;
}

static int tcp_toward_server(struct tcp_connection *conn, struct packet_info *p_info) {
	return conn->dst.ip == p_info->dst.ip && conn->dst.port == p_info->dst.port;
}

static void tcp_connection_handle_packet(struct packet_info *p_info) {
	struct tcp_connection *conn;

	if (p_info->type != PKT_PROTO_TCP)
		return;

	conn = tcp_connection_find(p_info);

	if (!conn) {
		if (!(p_info->tcp.flags & TCP_FLAG_RST)) {
			conn = tcp_connection_new(p_info);
			now(&conn->time_discovered);
			avl_insert(&tcp_connections, &conn->tcp_connections);
			if (p_info->tcp.flags & TCP_FLAG_SYN) {
				conn->state = TCP_STATE_INIT;
			}
		}
	} else {
		switch (conn->state) {
			case TCP_STATE_INIT:
				if (!tcp_toward_server(conn, p_info)) {
					// from server
					if ((p_info->tcp.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
						// complete handshake
						conn->state = TCP_STATE_CONNECTED;
						now(&conn->time_connected);
					}
					if (p_info->tcp.flags & TCP_FLAG_RST) {
						conn->state = TCP_STATE_REJECTED;
						now(&conn->time_disconnected);
					}
				}
				break;
			case TCP_STATE_CONNECTED:
				if (p_info->tcp.flags & TCP_FLAG_FIN) {
					if (tcp_toward_server(conn, p_info)) {
						conn->fin_c_to_s = 1;
					} else {
						conn->fin_s_to_c = 1;
					}
				}
				if ((p_info->tcp.flags & TCP_FLAG_RST) || (conn->fin_c_to_s && conn->fin_s_to_c)) {
					conn->state = TCP_STATE_CLOSED;
					now(&conn->time_disconnected);
				}
				break;
			default:
				break;
		}
	}
	if (conn)
		now(&conn->last_activity);
}

static void raw_socket_watch_cb(struct loop_watch* watch, enum loop_io_event events) {
	if (events & EVENT_READ) {
		struct sockaddr_ll sockaddr = { 0 };
		socklen_t socklen = sizeof(sockaddr);
		ssize_t packet_size;

		packet_size = recvfrom(watch->fd, &packet, sizeof(packet), MSG_TRUNC, (struct sockaddr *)&sockaddr, &socklen);
		if (packet_size < 0) {
			perror("recvfrom");
			return;
		}
		// if (packet_size > sizeof(packet)) {
		// 	fprintf(stderr, "truncated packet\n");
		// }
		if (ntohs(sockaddr.sll_protocol) == ETH_P_IP) {
			struct packet_info info = { 0 };

			packet_dissect(&info);
			tcp_connection_handle_packet(&info);
			// packet_print(&info);
		}
	}
}

static void print_status(struct loop_timeout *t) {
	struct tcp_connection *conn;

	printf("\033[2J");
	avl_for_each_element(&tcp_connections, conn, tcp_connections) {
		tcp_connection_print(conn);
	}

	loop_timeout_add(t, 1000);
}

int main(int argc, char **argv) {
	const char *ifname;
	int ifindex;
	struct loop_watch watch = { 0 };
	struct loop_timeout timeout = { 0 };

	if (argc != 2) {
		fprintf(stderr, "missing interface name\n");
		return 1;
	}

	ifname = argv[1];

	ifindex = if_nametoindex(ifname);

	if (ifindex == 0) {
		perror("if_nametoindex");
		return 1;
	}

	watch.cb = &raw_socket_watch_cb;
	watch.fd = bind_socket(ifindex);

	if (watch.fd < 0)
		return 1;

	loop_watch_set(&watch, EVENT_READ);

	timeout.cb = &print_status;
	loop_timeout_add(&timeout, 0);

	loop_run();

	return 0;
}

