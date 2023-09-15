# grant-and-claim-netns-interfaces

## Description

A system utility for moving network interfaces between network namespaces.  An
example of this would be to move a physical interface from the root netns into
a netns created by an unprivileged user, which lets the user configure the
interface, giving flexibility in immutable or otherwise access-restricted
environments.

In this program, the namespaces are named as such,
* "Claimee" - This is the netns in which the program is started. Namely, the
	one linked by `/proc/self/ns/net`.
* "Grantee" - This netns is the one linked by `/proc/$PID/ns/net`, in which
	`$PID` is discovered by running the executable configured with
	`GranteePIDDiscovery`


## Prerequisites

* libmnl-dev ([debian](https://packages.debian.org/search?keywords=libmnl-dev))
	or libmnl-devel
	([fedora](https://packages.fedoraproject.org/pkgs/libmnl/libmnl-devel/))
* libcap-dev ([debian](https://packages.debian.org/search?keywords=libcap-dev))
	or libcap-devel
	([fedora](https://packages.fedoraproject.org/pkgs/libcap/libcap-devel/))

## Installation

Either download and extract a release, or prepare the cloned repo with
`autoreconf --install`, and follow the release installation guide.

From releases
```
./configure
make install
```
