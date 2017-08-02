---
layout: post
title: "Build your very own SRv6 probe"
date: 2017-07-29 17:39:48 -0700
comments: true
categories: SPRING IPv6
---

Yes, IPv6 strikes back! 

As it turns out SPRING can be instantiated in two different data planes: MPLS and IPv6 (SRv6). Most of the SR documentation you can find online is about MPLS and probably because that’s where networking vendors have put most of the effort. And indeed gains are huge when you apply SR to the MPLS dataplane, in particular for big operators. For years MPLS have been plagued with complex architectures that require a bunch of protocols and a huge amount of state... a scaling nightmare for those who want to do some serious traffic engineering. SR greatly simplifies some of these issues, although not without introducing some other  interesting problems in the process.

My favorite aspect of SRv6 is that you don’t need expensive gear to experiment with it or to deploy it in production, and to demonstrate that is the case, in this post we’re gonna be playing with a simple client/server UDP application capable of sending SRv6 enabled packets throughout the network. If you’re wondering why would you want to use SRv6 in the first place, you can refer to this [draft](https://tools.ietf.org/html/draft-ietf-spring-ipv6-use-cases-11) where you can find some interesting use cases.

In the first part of this post we’ll be talking about the SRv6 implementation in Linux and then we’ll move on to discuss some code to implement our example application. Not all details will be covered as some basic knowledge is assumed on segment routing and C but a list of useful reading materials will be provided in the [References](#references) section. In this post the terms SR and SPRING are used to refer to [draft-ietf-spring-segment-routing-12](draft-ietf-spring-segment-routing-12) and the term SRv6 is used to refer to [draft-ietf-6man-segment-routing-header-07](https://tools.ietf.org/html/draft-ietf-6man-segment-routing-header-07)

<!-- TOC -->

  - [Topology](#topology)
- [Part 1](#part-1)
    - [Linux](#linux)
    - [Iproute2](#iproute2)
    - [SRv6 and the IPv6 socket api](#srv6-and-the-ipv6-socket-api)
- [Part 2](#part-2)
    - [The client](#the-client)
    - [The server](#the-server)
- [Final considerations](#final-considerations)
- [References](#references)

<!-- /TOC -->


## Topology

The image below shows the topology that we’ll be using throughout this post. All three nodes are Linux instances running the latest kernel. srv6-2-vm (node 2) acts as a routing bridge between srv6-vm (node 1) and srv6-3-vm (node 3). Nodes 1 and 3 don’t have any routes pointing at each other’s networks.

![topology]({{ site.url }}/assets/img/srv6.jpg)


# Part 1

### Linux

SR was released in February this year as part of the Linux kernel 4.10 version through a series of changes submitted by David Lebrun : [commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1ababeba4a21f3dba3da3523c670b207fb2feb62)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=915d7e5e5930b4f01d0971d93b9b25ed17d221aa)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c8702c60b88651072460f3f4026c7dfe2521d12)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=bf355b8d2c30a289232042cacc1cfaea4923936c)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f4853dc1c9c1994f6f756eabdcc25374ff271d9)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9baee83406d6a4b02222f5ee21511c3f4c19e39d)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=613fa3ca9e9e6af57927dab238121010c510fe4c)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a149e7c7ce812561f0fdc7a86ddc42f294e5eb3e)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f4853dc1c9c1994f6f756eabdcc25374ff271d9)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8bc66a4423dba1ffafddd52b68ddad4adff39648)
[commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=46738b1317e169b281ad74690276916e24d1be6d)

The implementation allows a SR enabled Linux machine to act as a segment Endpoint as well as an egress node. Both cases are defined by [draft-ietf-6man-segment-routing-header](https://tools.ietf.org/html/draft-ietf-6man-segment-routing-header-07) and the End functionality can be resumed as follows:

{% highlight C linenos %}
IF SegmentsLeft > 0 THEN
    decrement SL
    update the IPv6 DA with SRH[SL]
    FIB lookup on updated DA
    forward accordingly to the matched entry
ELSE
    drop the packet
{% endhighlight %}

* SL: Segments Left
* DA: Packet’s destination address
* SRH: Type 4 routing header

A Linux kernel instance can then act as any of the following:

* Source node: A node originating an IPv6 packet with an SRH (Type 4 segment routing header). This extension header may be injected “inline” or by encapsulating the original packet and adding an SRH.
* Transit node: Basically any node not inspecting a type 4 SRH (eg the node it’s not in the packet’s destination address DA)
* Endpoint node: A node receiving an IPv6 packet whose DA exists in the node’s local segment identifiers (SID) table.

According to [draft-filsfils-spring-srv6-network-programming](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming-01), an SRv6 node should maintain a local SID (segment identifier) table containing all the local SRv6 segments explicitly instantiated at node N; but the table isn't necessarily populated by default with all the IPv6 interface addresses. By default, according to the kernel [documentation](https://github.com/torvalds/linux/blob/8fa3b6f9392bf6d90cb7b908e07bd90166639f0a/Documentation/networking/seg6-sysctl.txt), SRv6 processing is disabled on every interface and must be explicitly enabled via /proc/sys/net/conf/\<iface\>/seg6_enabled. If a packet containing a SRH is received on a seg6-disabled interface, it's discarded. This validation is enforced by [ipv6_srh_rcv](https://github.com/torvalds/linux/blob/bc78d646e708dabd1744ca98744dea316f459497/net/ipv6/exthdrs.c#L323), in particular in these few lines:

{% highlight C linenos %}
	accept_seg6 = net->ipv6.devconf_all->seg6_enabled;
	if (accept_seg6 > idev->cnf.seg6_enabled)
		accept_seg6 = idev->cnf.seg6_enabled;

	if (!accept_seg6) {
		kfree_skb(skb);
		return -1;
{% endhighlight %}

 Other implementations like [FD.IO](https://docs.fd.io/vpp/17.04/sr_doc.html) create a SID local table and assign the desired function to each segment.

There are basically two ways to inject, inspect or remove a type 4 SRH in the current kernel implementation: using the well known iproute2 interface or through the IPv6 socket API. The former is implemented via [lightweight tunnels](https://lwn.net/Articles/650778/): this feature allows user space tools like iproute2 to customize the [input](https://github.com/torvalds/linux/blob/5518b69b76680a4f2df96b1deca260059db0c2de/net/ipv6/seg6_iptunnel.c#L234) and [output](https://github.com/torvalds/linux/blob/5518b69b76680a4f2df96b1deca260059db0c2de/net/ipv6/seg6_iptunnel.c#L275) function pointers that every route has in the linux kernel. Using [rtnetlink](http://man7.org/linux/man-pages/man7/rtnetlink.7.html) sockets, iproute2 passes the user specified SRH to the kernel so that after header [validation](https://github.com/torvalds/linux/blob/5518b69b76680a4f2df96b1deca260059db0c2de/net/ipv6/seg6.c#L32) the new input/ouput pointer functions can be installed. These functions do the heavy lifting of adding/removing/modifying the SR extension header. This is the same mechanism used by the MPLS and VXLAN [implementations](https://kernelnewbies.org/Linux_4.3#head-c5506dbfb2f3c214e689a53e1430873fe3ace52f) in the kernel. 

### Iproute2

The use of iproute2 is pretty straightforward. Based on our three-node topology, let’s assume that we want to ping srv6-3-vm from srv6-vm, going through node srv6-2-vm. As noted before there are no routes designating srv6-2-vm as the default gateway on either side (srv6-3-vm and srv6-vm). The following command adds a SR path on srv6-vm with destination srv6-3-vm specifying 2001:db8::2 as the next segment.


```
sr6@sr6-vm:~$ sudo ip -6 route add  2001:db9::1/64 dev eth1 encap seg6 mode encap segs 2001:db8::2
```

After issuing the command above, the routing table now shows our new SRv6 route.

```
sr6@sr6-vm:~$ ip -6 route list
2001:db8::/64 dev eth1  proto kernel  metric 256 
2001:db9::/64 dev eth1  metric 1024 
fe80::/64 dev eth1  proto kernel  metric 256 
ff00::/8 dev eth0  metric 256 
ff00::/8 dev eth1  metric 256 
```


A similar command is executed on srv6-3-vm for the return path.

```
sr6@sr6-3-vm:~$ sudo ip -6 route add  2001:db8::1/64 dev eth1 encap seg6 mode encap segs 2001:db9::2
```

In the examples above, the keywords **encap seg6** indicate that we want to use SRv6 and the option **mode encap** tells the kernel that we want to use the encapsulation mode.

Wireshark tells us a similar story:

{% highlight C linenos %}
Frame 5: 120 bytes on wire (960 bits), 120 bytes captured (960 bits)
Linux cooked capture
Internet Protocol Version 6, Src: 2001:db8::1, Dst: 2001:db9::1
    0110 .... = Version: 6
    .... 0000 0000 .... .... .... .... .... = Traffic class: 0x00 (DSCP: CS0, ECN: Not-ECT)
    .... .... .... 0100 0000 0100 0010 0010 = Flow label: 0x40422
    Payload length: 64
    Next header: Routing Header for IPv6 (43)
    Hop limit: 63
    Source: 2001:db8::1
    Destination: 2001:db9::1
    [Source GeoIP: Unknown]
    [Destination GeoIP: Unknown]
    Routing Header for IPv6 (Segment Routing)
        Next Header: UDP (17)
        Length: 4
        [Length: 40 bytes]
        Type: Segment Routing (4)
        Segments Left: 0
        First segment: 1
        Flags: 0x0000
        Reserved: 00
        Address[0]: 2001:db9::1
        Address[1]: 2001:db8::2
        [Segments in Traversal Order]
User Datagram Protocol, Src Port: 51129, Dst Port: 2000
    Source Port: 51129
    Destination Port: 2000
    Length: 24
    Checksum: 0x7e26 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 2]
Data (16 bytes)
    Data: 48656c6c6f2c2049276d20686572650a
    [Length: 16]
{% endhighlight %}

From the output above we can easily see where this packet capture was taken. Note “Segments left” (line 19) is 0 and how the segment list (lines 23 and 24) is encoded in the reverse order of the traversed path.


### SRv6 and the IPv6 socket api

The other way to interact with SRH4 in the kernel is through the sockets API. Depending on the socket type, control data related to a packet’s payload can be transmitted or received as ancillary data using the [sendmsg](https://linux.die.net/man/2/sendmsg) and [recvmsg](https://linux.die.net/man/2/recvmsg) system calls. However, for the purposes of this post, our UDP application will be injecting the same segment routing header to packets sent through the same socket, so instead of sending the SRH in every call to _sendmsg()_, we’ll set the ancillary data as a socket option. This turns our extension header into a  _sticky_ option. Note that if you’re planning to use a TCP socket, ancillary data is never sent or received by _sendmsg()_ and _rcvmsg()_ calls. This is best explained by RFC 3542:

```
  It is not possible to use ancillary data to transmit the above
   options for TCP since there is not a one-to-one mapping between send
   operations and the TCP segments being transmitted.  Instead an
   application can use setsockopt to specify them as sticky options.
   When the application uses setsockopt to specify the above options it
   is expected that TCP will start using the new information when
   sending segments.  However, TCP may or may not use the new
   information when retransmitting segments that were originally sent
   when the old sticky options were in effect.

   It is unclear how a TCP application can use received information
   (such as extension headers) due to the lack of mapping between
   received TCP segments and receive operations.  In particular, the
   received information could not be used for access control purposes
   like on UDP and raw sockets.
```


The [ancillary data structure](http://man7.org/linux/man-pages/man3/cmsg.3.html) can be a bit confusing at first. It basically consists of a series of _cmsghdr_ structures describing control information passed from the kernel to the userland interface or viceversa. The control data may be IP options, various fields in the IP header or data not sent on the wire, like the packet’s incoming interface. The actual data is usually consumed by POSIX defined macros to facilitate access to the underlying structures. One of the reasons why _cmsghdr_ can be confusing is because some of the fields are **value-result**, which is just a fancy way of calling fields that take a pointer to a certain struct that the kernel will use to write data to. This data is then consumed by the userspace application. [Steven’s Unix Network Programming](https://www.amazon.com/Unix-Network-Programming-Sockets-Networking/dp/0131411551/ref=pd_lpo_sbs_14_t_0?_encoding=UTF8&psc=1&refRID=7V8D8GGFF0G25E1VC7TE) goes into a great deal of detail on this subject.

The general idea used by our example app is that once the socket is created via  [socket()](http://man7.org/linux/man-pages/man2/socket.2.html), we specify the IP option that we want to send or receive using a call to [setsockopt()](https://linux.die.net/man/2/setsockopt). In our case, the client, which will be setting the SRH in inline mode, will use IPV6\_RTHDR, while the server will call _setsockopt()_ with IPV6\_RECVRTHDR to indicate the kernel that we want to receive the control information on our socket. This control information will give us access to the segment routing header that we want to process.

One thing to keep in mind is that the existing [glibc implementation](https://sourceware.org/git/?p=glibc.git;a=blob;f=inet/inet6_rth.c;h=917753da09f5897ffcd05c14195791e392edb81a;hb=HEAD) contains a series of functions, first defined 20 yrs ago by Richard Stevens in [RFC 2292](https://www.ietf.org/rfc/rfc2292.txt) § 8 and then updated by [RFC 3542](https://www.ietf.org/rfc/rfc3542.txt) § 7, that were meant to abstract the handling of the IPv6 routing headers, but at the time SRH type 4 wasn’t defined yet!  This means that you won’t be able to take advantage of these functions to construct a SRv6 routing header.

# Part 2

### The client

Our application consists of a client that injects a SRH with a user defined segment list (or hops to traverse) The server then parses the SRH received and prints the segment list (or traversed hops) to the screen. You can access the source code on [github](https://github.com/ruissalo/srv6_app) so we’ll discuss only a few  relevant sections here.

The following struct is used to represent a segment routing extension header.  Line 11 represents the list of segments to traverse or segments traversed as an array of [in6_addr](http://man7.org/linux/man-pages/man7/ipv6.7.html) structures.

{% highlight C linenos %}
struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flag_1;
        __u8    flag_2;
        __u8    reserved;

        struct in6_addr segments[0];
};
{% endhighlight %}
{% highlight C linenos %}

    srh->nexthdr = 17;
    srh->hdrlen = 4;
    srh->type = 4;
    srh->segments_left = 1;
    srh->first_segment = 1;
    srh->flag_1 = 0;
    srh->flag_2 = 0;
    srh->reserved = 0;

    memset(&srh->segments[0], 0, sizeof(struct in6_addr));
    inet_pton(AF_INET6, segment, &srh->segments[1]);
{% endhighlight %}

In the previous code block we populate _srh_, our _ipv6_sr_hdr_ struct, with the routing header information we want to attach to the packets. Since we’re traversing a single hop, _segmens\_left_ is 1. In line 11 we convert the user provided segment (an IPv6 address or 2001:db8::2 in the three-node topology) into network form using [inet_pton()](http://man7.org/linux/man-pages/man3/inet_pton.3.html) and the result is stored in the segment list of the _srh_ struct.

Next, line 1 creates the the UDP socket descriptor and finally line 2 sets the _srh_ struct as a sticky option on the socket. All the packets sent through this socket will now have a segment routing extension header following the 40 octets IPv6 header.

{% highlight C linenos %}
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len);
{% endhighlight %}

This last code block uses the [sendto()](https://linux.die.net/man/2/sendto) system call to relay a message to the server.
{% highlight C linenos %}
    n = sendto(fd, buffer, buffer_size, 0, (struct sockaddr *) &sin6, sizeof(sin6));
    if (n < 0) {
        perror("Error sending UDP message");
        return -1;
    }
{% endhighlight %}


### The server

Just like our client, the server creates a socket and sets IPV6_RECVRTHDR to indicate the kernel that we want to receive ancillary data.


{% highlight C linenos %}
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on));
    if (err < 0) {
        perror("setsockopt error");
        close(fd);
        return -1;
    }
   err = bind(fd, (struct sockaddr *)&sin6_bind, sizeof(sin6_bind));
{% endhighlight %}

This code block initializes the _cmsghdr_ and _msghdr_ structs used to store the received SRH. A call to _recvmsg()_ in line 26 passes _msg_ as a reference to store the data.

{% highlight C linenos %}
void srh_print(int sockfd)
{
   int    rc;
   struct msghdr  msg;
   struct cmsghdr *cmsg;

  int iov_number;
  struct iovec iov_data[1];
  char buffer[1024];
  
  bzero(&msg, sizeof(msg));
  iov_data[0].iov_base = buffer;
  iov_data[0].iov_len = 1024;
  iov_number = 1;

  char control[1024];

  struct sockaddr_in6 client_address;

  msg.msg_iov = iov_data;
  msg.msg_iovlen = iov_number;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  msg.msg_name = NULL;

   rc = recvmsg(sockfd, &msg, 0);
{% endhighlight %}


Once _recvmsg()_ returns, we can iterate over the ancillary data returned by the kernel in _msg_ to print the traversed segments to the screen. CMSG\_FIRSTHDR, CMSG\_NXTHDR and CMSG\_DATA are the macros defined in RFC 3542 that we mentioned in the previous section. Note that these macros turn the API into a functional interface, so the application doesn’t really need to bother about understanding the underlying structures. Lines 3 and 4 check the control message type is IPV6\_RTHDR and then line 5 calls CMSG\_DATA() to get a pointer to the data. The next line casts the data into our _ipv6\_sr\_hdr_ struct. Finally lines 7 and 8 convert the IPv6 segments from network to presentation before printing the addresses to the screen.


{% highlight C linenos %}
         for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
              cmsg = CMSG_NXTHDR (&msg, cmsg))  {
             if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                 cmsg->cmsg_type == IPV6_RTHDR)  {
                  data = CMSG_DATA(cmsg);
                  struct ipv6_sr_hdr *rthdr = (struct ipv6_sr_hdr *) data;
                  inet_ntop(AF_INET6, &rthdr->segments[0], str, sizeof(str));
                  inet_ntop(AF_INET6, &rthdr->segments[1], str1, sizeof(str1));
                  printf("%s \n", str);
                  printf("%s \n", str1);
                 if (msg.msg_flags & MSG_CTRUNC)
                     printf(" (control info truncated)");
             }
        }
{% endhighlight %}

After running the client, the server handles the connection and prints the following information to the screen
before exiting.

{% highlight C linenos %}
sr6@sr6-3-vm:~$ ./server.out 2001:db9::1 3000
header len is 4
header type is 4
next header 17
first segment is 1
reserved is 0
2001:db9::1 
2001:db8::2 
{% endhighlight %}

# Final considerations

* While we used inline mode in this post, take into account that only endhosts should use this insertion mode. Encapsulation should otherwise be the prefered method when packets enter a SR domain.

* Nothing prevents you from simultaneously installing SRv6 static routes and having your application use different SRH values. You 
must enforce consistency between the system config and your applications.

* In general SPRING terminology a segment may carry topological meaning but it also may indicate a logical function provided by the host or the network (aka SRv6 Network Programming). This posts dealt exclusively with the Endpoint function. You can read more about SRv6 network programming functions in [draft-filsfils-spring-srv6-network-programming](https://tools.ietf.org/html/draft-filsfils-spring-srv6-network-programming-01)

* This post purposely omits any comments or implementation details regarding the acquisition of segment ids (SIDS) from the network. In the next post we'll discuss
some options to make this information available to a central controller for path computation and path programming on the probes.


# References


1. Linux SRv6 lwtunnels implementation can be mainly found [here](https://github.com/torvalds/linux/blob/5518b69b76680a4f2df96b1deca260059db0c2de/net/ipv6/seg6_iptunnel.c#L275)

2. For SRv6 socket options you can start [here](https://github.com/torvalds/linux/blob/5518b69b76680a4f2df96b1deca260059db0c2de/net/ipv6/exthdrs.c#L866)

3. A great resource to learn about UNIX sockets is [Steven’s Unix Network Programming](https://www.amazon.com/Unix-Network-Programming-Sockets-Networking/dp/0131411551/ref=pd_lpo_sbs_14_t_0?_encoding=UTF8&psc=1&refRID=7V8D8GGFF0G25E1VC7TE). Highly recommended.

4. Advanced Sockets Application Program Interface (API) for IPv6. https://www.ietf.org/rfc/rfc3542.txt

5. IPv6 Segment Routing Header (SRH) https://tools.ietf.org/html/draft-ietf-6man-segment-routing-header-07

6. http://segment-routing.org/

7. IPv6 segment routing https://lwn.net/Articles/722804/

8. https://inl.info.ucl.ac.be/publications/implementing-ipv6-segment-routing-linux-kernel

9. https://www.amazon.com/Linux-Programming-Interface-System-Handbook/dp/1593272200



**and special thanks to David Lebrun for answering my questions.**