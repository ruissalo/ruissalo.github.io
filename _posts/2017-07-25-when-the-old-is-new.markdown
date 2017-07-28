---
layout: post
title: "When old is the new new"
date: 2017-07-25 17:39:48 -0700
comments: true
categories: SPRING, IPv6
---

As you well know technology comes and goes in cycles and sometimes it makes you wonder why certain things didn’t gain traction in the first place, only to have someone come in later and “discover” a brand new piece of tech. Maybe it’s the market, or the technology landscape that changes creating new opportunities, in any case, RFCs need to be published, scientific papers need to be written and vendors need to innovate constantly. 

Segment routing is a very good example of something old, at least the basic idea around it, that is now becoming a trend. The concept of source routing was discussed and covered some 35 years ago by RFC 791 and implemented as IP option 131. Basically this option allows the originating system to specify intermediate systems a packet must traverse to get to its destination [^1]. Later on a number of thread vectors were identified, notably described by RFC 6274  [^2], and the option is basically deprecated today. 

IPv6 also had a similar feature in the form of an extension header. Before SR, there were two main types of this routing header: RH0 and RH2[^4]. RH0 was also deprecated due to similar security concerns[^5]

Fast forward to 2015, the first version of SPRING [^3] appears and the first segment routing presentations start popping up on youtube. SPRING leverages the same source routing paradigm that allows a node to direct packets through an ordered list of segments. One notable difference with the old IP option 131 is the fact these segments may represent not only topological information but also a service of some sort, which in turn can have local (node only) or global (network-wide) significance.

SPRING’s architecture is basically meant to operate within the boundaries of a single administrative domain where all nodes are trusted, in theory at least, so the  thread model and attacks that applied to the original IP option are not the same anymore. Moreover, the presence of an HMAC TLV field in the IPv6 segment routing header allows nodes to determine the validity of a given segment routing header.

And by the way, IPv6 just resuscitated from the dead this month, checkout RFC 8200.

 [^1]:  https://tools.ietf.org/html/rfc791
 [^2]: https://tools.ietf.org/html/rfc6274
 [^3]: https://tools.ietf.org/html/draft-ietf-spring-segment-routing-12
 [^4]: https://tools.ietf.org/html/rfc6554
 [^5]: https://tools.ietf.org/html/rfc5095
