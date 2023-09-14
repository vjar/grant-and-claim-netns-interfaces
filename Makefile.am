bin_PROGRAMS = grant-and-claim-netns-interfaces
grant_and_claim_netns_interfaces_SOURCES = src/main.c
grant_and_claim_netns_interfaces_LDADD = -lmnl
dist_libexec_SCRIPTS = grant-and-claim-netns-interfaces-targetpid-discovery-podman
dist_sysconf_DATA = grant-and-claim-netns-interfaces.conf
dist_noinst_FILES = README.md

sysconfdir = /etc

install-exec-hook:
	setcap cap_dac_override,cap_net_admin,cap_sys_admin=eip $(DESTDIR)$(bindir)/grant-and-claim-netns-interfaces
