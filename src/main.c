#define _GNU_SOURCE
#include <stdint.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/wait.h>

int32_t wait_for_child(int32_t *pRv) {
	int32_t wstatus;
	waitpid(
		/* pid: wait on any pid */ -1,
		/* wstatus */ &wstatus,
		/* options */ 0
	);
	if (pRv != NULL) {
		*pRv = WEXITSTATUS(wstatus);
	}
	if (wstatus) {
		fprintf(stderr, "wait status unsuccessful, exit code %d\n", WEXITSTATUS(wstatus));
		return 1;
	}
	return 0;
}

int32_t discover_target_pid(int32_t *pPid, const char *pid_discovery_exec, char *argv[], int32_t *infd, int32_t *outfd) {
	if (pipe(infd) == -1) {
		perror("pipe");
		return 1;
	}

	if (pipe(outfd) == -1) {
		perror("pipe");
		return 1;
	}

	// infd[0] = readable fd of child's stdin
	// infd[1] = writable fd of child's stdin
	// outfd[0] = readable fd of child's stdout
	// outfd[1] = writable fd of child's stdout
	if (fork() == 0) {
		// closes for the unused duplicates created by fork
		if (close(infd[1])) { perror("close"); exit(1); }
		if (close(outfd[0])) { perror("close"); exit(1); }

		if (dup2(infd[0], STDIN_FILENO) == -1) { perror("dup2"); exit(1); }
		if (dup2(outfd[1], STDOUT_FILENO) == -1) { perror("dup2"); exit(1); }
		// closes for the ones left open after duplicating over the
		// standard streams
		if (close(infd[0])) { perror("close"); exit(1); }
		if (close(outfd[1])) { perror("close"); exit(1); }

		if (execve(pid_discovery_exec,
			argv,
			&(char*){ NULL }
		)) {
			perror("execve");
			exit(1);
		}
		exit(0);
	} else {
		if (close(infd[0])) { perror("close"); exit(1); }
		if (close(outfd[1])) { perror("close"); exit(1); }

		char buf[16];
		int64_t nbytes = read(outfd[0], buf, sizeof(buf));
		if (nbytes == -1) {
			perror("read");
			return 1;
		}

		buf[nbytes] = '\0';

		int32_t pid = atoi(buf);
		if (pid <= 0) {
			fprintf(stderr, "child wrote invalid pid \"%s\"\n", buf);
			return 1;
		}
		*pPid = pid;
		return 0;
	}
}

int32_t open_grantee_nsfd(const char *pid_discovery_exec, char *argv[], int32_t *nsfd) {
	int32_t target_pid;
	int32_t infd[2];
	int32_t outfd[2];
	char path[256];
	int32_t nbytes;

	if (discover_target_pid(&target_pid, pid_discovery_exec, argv, infd, outfd)) { return 1; }

	nbytes = snprintf(path, sizeof(path), "/proc/%d/ns/net", target_pid);
	assert(nbytes != -1 && (uint64_t)nbytes < sizeof(path));
	*nsfd = open(path, O_RDONLY | O_CLOEXEC);

	close(infd[1]);
	close(outfd[0]);
	if (wait_for_child(NULL)) { return 1; }
	return 0;
}

int32_t nl_set_interface_namespace(const char *ifname, uint32_t nsfd) {
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

	// TODO: attribute padding required due to some alignment mistake
	mnl_attr_put_u32(nlh, 0, 0);
	mnl_attr_put_u32(nlh, IFLA_NET_NS_FD, nsfd);
	mnl_attr_put_str(nlh, IFLA_IFNAME, ifname);
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
		// TODO: ENODEV is fine
		perror("RTNETLINK answers");
		return 1;
	}

	mnl_socket_close(nl);
	return 0;
}

int32_t main(int32_t, char *argv[]) {
	// parse configuration
	static char *grantee_pid_discovery = "/bin/macvtap-mknod-targetpid-discovery";

	int32_t grantee_net = 0;
	if (open_grantee_nsfd(grantee_pid_discovery, argv, &grantee_net)) { return 1; }

	int32_t claimee_net = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (claimee_net == -1) {
		perror("open");
		return 1;
	}

	if (nl_set_interface_namespace("tap0", (uint32_t)grantee_net)) {
		// ok
	}

	if (setns(grantee_net, CLONE_NEWNET)) {
		perror("setns");
		return 1;
	}

	if (nl_set_interface_namespace("tap0", (uint32_t)claimee_net)) { return 1; }
	close(grantee_net);
	close(claimee_net);
	return 0;
}
