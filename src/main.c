#define _GNU_SOURCE
#include <stdint.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <net/if.h>
#include <ctype.h>

typedef struct config {
	char grantee_pid_discovery[256];
	char grant_ifaces[256];
	char claim_ifaces[256];
} config_t;

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
		return 1;
	}

	mnl_socket_close(nl);
	return 0;
}

int32_t set_ifnames_netns(char *space_separated_list, uint32_t nsfd) {
	char *ifname = strtok(space_separated_list, " ");
	while (ifname != NULL) {
		if (nl_set_interface_namespace(ifname, nsfd)) {
			bool fatal = true;
			if (errno == ENODEV) { fatal = false; }
			perror("RTNETLINK answers");
			fprintf(stderr, "could not set %s netnsfd %d\n", ifname, nsfd);
			if (fatal) { return 1; }
		}
		ifname = strtok(NULL, " ");
	}
	return 0;
}

int32_t parse_configuration(const char *conf, config_t *parsed) {
	char linebuf[256];
	uint32_t line_len = strchr(conf, '\n') - conf;
	const char *nextline = conf;
	char *endofconf = strchr(conf, '\0');
	while (line_len < sizeof(linebuf)) {
		memcpy(linebuf, nextline, line_len);
		linebuf[line_len] = '\0';

		if (line_len > 0) {
			int64_t keylen = strchr(linebuf, '=') - linebuf;
			if (keylen < 0) {
				fprintf(stderr, "unable to parse configuration: malformed line %s\n", linebuf);
				return 1;
			}
			linebuf[keylen] = '\0';
			char *key = linebuf;
			char *value = &linebuf[keylen + 1];

			if (strcmp(key, "GranteePIDDiscovery") == 0) {
				strncpy(parsed->grantee_pid_discovery, value, sizeof(parsed->grantee_pid_discovery));
			} else if (strcmp(key, "GrantInterfaces") == 0) {
				strncpy(parsed->grant_ifaces, value, sizeof(parsed->grant_ifaces));
			} else if (strcmp(key, "ClaimInterfaces") == 0) {
				strncpy(parsed->claim_ifaces, value, sizeof(parsed->claim_ifaces));
			} else {
				fprintf(stderr, "unable to parse configuration: unknown key %s\n", key);
			}
		}

		nextline += line_len + 1;
		char *endofline = strchr(nextline, '\n');
		if (endofline == NULL) {
			endofline = endofconf;
		}
		if (endofline > endofconf) { break; }
		line_len = endofline - nextline;
	}
	return 0;
}

int32_t open_and_parse_configuration(config_t *config) {
	int32_t fd;
	struct stat sb;
	char *contents;
	fd = open(CONF_FILE, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	if (fstat(fd, &sb) == -1) {
		perror("fstat");
		return 1;
	}

	if (sb.st_size < 0) { return 1; }

	contents = mmap(NULL,
		(uint64_t)sb.st_size,
		PROT_READ,
		MAP_PRIVATE,
		fd,
		0
	);

	if (parse_configuration(contents, config)) { return 1; }

	munmap(contents, (uint64_t)sb.st_size);
	close(fd);
	return 0;
}

// https://github.com/torvalds/linux/blob/3a1e2f4/net/core/dev.c#L1028
bool dev_valid_name(const char *name) {
        if (*name == '\0')
                return false;
        if (strnlen(name, IFNAMSIZ) == IFNAMSIZ)
                return false;
        if (!strcmp(name, ".") || !strcmp(name, ".."))
                return false;

        while (*name) {
                if (*name == '/' || *name == ':' || isspace(*name))
                        return false;
                name++;
        }
        return true;
}

int32_t verify_valid_ifnames(char *space_separated_list, uint64_t listsz) {
	char copy[listsz];
	memcpy(copy, space_separated_list, listsz);
	copy[listsz-1] = '\0';

	char *ifname = strtok(copy, " ");
	while (ifname != NULL) {
		if (!dev_valid_name(ifname)) {
			fprintf(stderr, "malformed ifname %s\n", ifname);
			return 1;
		}
		ifname = strtok(NULL, " ");
	}
	return 0;
}

int32_t main(int32_t, char *argv[]) {
	config_t *config = &(config_t){0};
	if (open_and_parse_configuration(config)) { return 1; }
	if (verify_valid_ifnames(config->grant_ifaces, sizeof(config->grant_ifaces))) { return 1; }
	if (verify_valid_ifnames(config->claim_ifaces, sizeof(config->claim_ifaces))) { return 1; }

	int32_t grantee_net = 0;
	if (open_grantee_nsfd(config->grantee_pid_discovery, argv, &grantee_net)) { return 1; }

	int32_t claimee_net = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (claimee_net == -1) {
		perror("open");
		return 1;
	}

	if (set_ifnames_netns(config->grant_ifaces, (uint32_t)grantee_net)) { return 1; }

	if (setns(grantee_net, CLONE_NEWNET)) {
		perror("setns");
		return 1;
	}

	if (set_ifnames_netns(config->claim_ifaces, (uint32_t)claimee_net)) { return 1; }
	close(grantee_net);
	close(claimee_net);
	return 0;
}
