bin_PROGRAMS = grant-and-claim-netns-interfaces
grant_and_claim_netns_interfaces_SOURCES = src/main.c
grant_and_claim_netns_interfaces_LDADD = -lmnl
dist_noinst_FILES = README.md

install-exec-hook:
	setcap CAP_NET_ADMIN=ep $(DESTDIR)$(bindir)/grant-and-claim-netns-interfaces
