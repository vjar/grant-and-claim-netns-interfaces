#define _GNU_SOURCE
#include <stdint.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>

int32_t nl_set_interface_namespace(int32_t , int32_t) {
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifh;
		char attr_buf[512];
	} request;
	struct nlmsghdr *nlh;
	struct mnl_socket *nl;
	int32_t rv;
	uint32_t nbytes;

	nlh = mnl_nlmsg_put_header(&request);
	nlh->nlmsg_type = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	struct ifinfomsg *ifh = mnl_nlmsg_put_extra_header(nlh, sizeof(ifh));
	ifh->ifi_family = AF_UNSPEC;
	ifh->ifi_change = 0;

	int32_t nsfd = open("/proc/75653/ns/net", O_RDONLY | O_CLOEXEC);
	if (nsfd == -1) {
		perror("open");
		return 1;
	}
	// TODO: attribute padding required due to some alignment mistake
	mnl_attr_put_u32(nlh, 0, 0);
	mnl_attr_put_u32(nlh, IFLA_NET_NS_FD, (uint32_t)nsfd);
	mnl_attr_put_str(nlh, IFLA_IFNAME, "eno1");
	nbytes = mnl_nlmsg_size(mnl_nlmsg_get_payload_len(nlh));

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		return 1;
	}

	if (mnl_socket_bind(nl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return 1;
	}

	mnl_nlmsg_fprintf(stderr, nlh, nlh->nlmsg_len, sizeof(*ifh));

	rv = mnl_socket_sendto(nl, nlh, nbytes);
	if (rv != (int32_t)nbytes) {
		perror("mnl_socket_sendto");
		return 1;
	}

	char buf[512];
	nbytes = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (rv == -1) {
		perror("mnl_socket_recvfrom");
		return 1;
	}

	uint32_t portid = mnl_socket_get_portid(nl);
	if (mnl_cb_run(buf, nbytes, 0, portid, NULL, NULL) == -1) {
		perror("RTNETLINK answers");
		return 1;
	}

	mnl_socket_close(nl);
	close(nsfd);
	return 0;
}

int32_t main() {
	if (nl_set_interface_namespace(0, 0)) { return 1; }
	return 0;
}
