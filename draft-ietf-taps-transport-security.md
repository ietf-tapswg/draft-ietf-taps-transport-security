---
title: A Survey of the Interaction Between Security Protocols and Transport Services
abbrev: Transport Security Survey
docname: draft-ietf-taps-transport-security-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: T. Enghardt
    name: Theresa Enghardt
    org: TU Berlin
    street: Marchstr. 23
    city: 10587 Berlin
    country: Germany
    email: ietf@tenghardt.net
  -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: C. Perkins
    name: Colin Perkins
    org: University of Glasgow
    street: School of Computing Science
    city: Glasgow  G12 8QQ
    country: United Kingdom
    email: csp@csperkins.org
  -
    ins: K. Rose
    name: Kyle Rose
    org: Akamai Technologies, Inc.
    street: 150 Broadway
    city: Cambridge, MA 02144
    country: United States of America
    email: krose@krose.org
  -
    ins: C. A. Wood
    name: Christopher A. Wood
    email: caw@heapingbits.net

informative:
    WireGuard:
      title: WireGuard -- Next Generation Kernel Network Tunnel
      target: https://www.wireguard.com/papers/wireguard.pdf
      date: {DATE}
      author:
        -
          ins: J. A. Donenfeld
    ALTS:
      title: Application Layer Transport Security
      target: https://cloud.google.com/security/encryption-in-transit/application-layer-transport-security/
      date: {DATE}
      author:
        -
          ins: C. Ghali
        -
          ins: A. Stubblefield
        -
          ins: E. Knapp
        -
          ins: J. Li
        -
          ins: B. Schmidt
        -
          ins: J. Boeuf
    CurveCP:
      title: CurveCP -- Usable security for the Internet
      target: http://curvecp.org
      date: {DATE}
      author:
        -
          ins: D. J. Bernstein
    MinimaLT:
      title: MinimaLT -- Minimal-latency Networking Through Better Security
      target: http://dl.acm.org/citation.cfm?id=2516737
      date: {DATE}
      author:
        -
          ins: W. M. Petullo
          org: United States Military Academy, West Point, NY, USA
        -
          ins: X. Zhang
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: J. A. Solworth
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: D. J. Bernstein
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: T. Lange
          org: TU Eindhoven, Eindhoven, Netherlands
    OpenVPN:
      title: OpenVPN cryptographic layer
      date: {DATE}
      target: https://openvpn.net/community-resources/openvpn-cryptographic-layer/

--- abstract

This document provides a survey of commonly used or notable network security protocols, with a focus
on how they interact and integrate with applications and transport protocols. Its goal is to supplement
efforts to define and catalog transport services by describing the interfaces required to
add security protocols. This survey is not limited to protocols developed within the scope or context of
the IETF, and those included represent a superset of features a Transport Services system may need to support.

--- middle

# Introduction

Services and features provided by transport protocols have been cataloged in {{?RFC8095}}. This
document supplements that work by surveying commonly used and notable network security protocols,
and identifying the interfaces between these protocols and both transport protocols and
applications.  It examines Transport Layer Security (TLS), Datagram Transport Layer Security (DTLS),
IETF QUIC, Google QUIC (gQUIC), tcpcrypt, Internet Protocol Security (IPsec), Secure Real-time Transport Protocol (SRTP) with DTLS,
WireGuard, CurveCP, and MinimaLT. For each protocol, this document provides a brief description.
Then, it describes the interfaces between these protocols and transports in {{transport-interface}}
and the interfaces between these protocols and applications in {{application-interface}}.

Selected protocols represent a superset of functionality and features a Transport Services system may
need to support, both internally and externally (via an API) for applications {{?I-D.ietf-taps-arch}}. Ubiquitous
IETF protocols such as (D)TLS, as well as non-standard protocols such as gQUIC,
are included despite overlapping features. As such, this survey is not limited to protocols
developed within the scope or context of the IETF. Outside of this candidate set, protocols
that do not offer new features are omitted. For example, newer protocols such as WireGuard make
unique design choices that have implications and limitations on application usage. In contrast,
protocols such as ALTS {{ALTS}} are omitted since they do not provide interfaces deemed unique.

Authentication-only protocols such as TCP-AO {{?RFC5925}} and IPsec AH {{?RFC4302}} are excluded
from this survey. TCP-AO adds authenticity protections to long-lived TCP connections, e.g., replay
protection  with per-packet Message Authentication Codes. (This protocol obsoletes TCP MD5 "signature"
options specified in {{?RFC2385}}.) One prime use case of TCP-AO is for protecting BGP connections.
Similarly, AH adds per-datagram authenticity and adds similar replay protection. Despite these
improvements, neither protocol sees general use and both lack critical properties important for emergent
transport security protocols: confidentiality, privacy protections, and agility. Such protocols are thus
omitted from this survey.

## Goals

This survey is intended to help identify the most common interface surfaces between security protocols and
transport protocols, and between security protocols and applications.

One of the goals of Transport Services is to define a common interface for using transport protocols that allows
software using transport protocols to easily adopt new protocols that provide similar feature-sets. The survey of
the dependencies security protocols have upon transport protocols can guide implementations in determining
which transport protocols are appropriate to be able to use beneath a given security protocol. For example,
a security protocol that expects to run over a reliable stream of bytes, like TLS, restricts the set of transport
protocols that can be used to those that offer a reliable stream of bytes.

Defining the common interfaces that security protocols provide to applications also allows interfaces to be
designed in a way that common functionality can use the same APIs. For example, many security protocols
that provide authentication let the application be involved in peer identity validation. Any interface to use
a secure transport protocol stack thus needs to allow applications to perform this action during connection
establishment.

## Non-Goals

While this survey provides similar analysis to that which was performed for transport protocols in {{?RFC8095}},
it is important to distinguish that the use of security protocols requires more consideration.

It is not a goal to allow software implementations to automatically switch between different security protocols,
even where their interfaces to transport and applications are equivalent. Even between versions, security
protocols have subtly different guarantees and vulnerabilities. Thus, any implementation needs to only
use the set of protocols and algorithms that are requested by applications or by a system policy.

# Terminology

The following terms are used throughout this document to describe the roles and interactions of transport security protocols:

- Transport Feature: a specific end-to-end feature that the transport layer provides to an application.
Examples include confidentiality, reliable delivery, ordered delivery, and message-versus-stream orientation.

- Transport Service: a set of Transport Features, without an association to any given framing protocol,
which provides functionality to an application.

- Transport Protocol: an implementation that provides one or more different transport services using a
specific framing and header format on the wire. A Transport Protocol services an application.

- Application: an entity that uses a transport protocol for end-to-end delivery of data across the network.
This may also be an upper layer protocol or tunnel encapsulation.

- Security Protocol: a defined network protocol that implements one or more security features, such as
authentication, encryption, key generation, session resumption, and privacy. Security
protocols may be used alongside transport protocols, and in combination with other security protocols when
appropriate.

- Handshake Protocol: a protocol that enables peers to validate each other and to securely establish
shared cryptographic context.

- Record: Framed protocol messages.

- Record Protocol: a security protocol that allows data to be divided into manageable blocks and protected
using shared cryptographic context.

- Session: an ephemeral security association between applications.

- Connection: the shared state of two or more endpoints that persists across messages that are transmitted
between these endpoints. A connection is a transient participant of a session, and a session generally lasts
between connection instances.

- Peer: an endpoint application party to a session.

- Client: the peer responsible for initiating a session.

- Server: the peer responsible for responding to a session initiation.

# Transport Security Protocol Descriptions

This section contains brief descriptions of the various security protocols currently used to protect
data being sent over a network.  These protocols are grouped based on where in the protocol stack
they are implemented, which influences which parts of a packet they protect: Generic application
payload, application payload for specific application-layer protocols, both application payload and
transport headers, or entire IP packets.

Note that not all security protocols can be easily categorized, e.g., as some protocols can be used
in different ways or in combination with other protocols.
One major reason for this is that channel security protocols often consist of two components:

- A handshake protocol, which is responsible for negotiating parameters, authenticating the
  endpoints, and establishing shared keys.
- A record protocol, which is used to encrypt traffic using keys and parameters provided by the
  handshake protocol.

For some protocols, such as tcpcrypt, these two components are tightly integrated. In contrast, for
IPsec, these components are implemented in separate protocols: AH and ESP are record protocols,
which can use keys supplied by the handshake protocol IKEv2, by other handshake protocols, or by
manual configuration. Moreover, some protocols can be used in different ways: While the base TLS protocol as
defined in {{RFC8446}} has an integrated handshake and record protocol, TLS or DTLS can also be used
to negotiate keys for other protocols, as in DTLS-SRTP, or the handshake protocol can be used with
a separate record layer, as in QUIC.

## Application Payload Security Protocols

The following protocols provide security that protects application payloads sent over a
transport. They do not specifically protect any headers used for transport-layer functionality.

### TLS

TLS (Transport Layer Security) {{?RFC8446}} is a common protocol used to establish a secure session between two endpoints. Communication
over this session "prevents eavesdropping, tampering, and message forgery." TLS consists
of a tightly coupled handshake and record protocol. The handshake protocol is used to authenticate peers,
negotiate protocol options, such as cryptographic algorithms, and derive session-specific
keying material. The record protocol is used to marshal (possibly encrypted) data from one
peer to the other. This data may contain handshake messages or raw application data.

### DTLS

DTLS (Datagram Transport Layer Security) {{?RFC6347}} is based on TLS, but differs in that
it is designed to run over unreliable datagram protocols like UDP instead of TCP.
DTLS modifies the protocol to make sure it can still provide the same security guarantees as TLS
even without reliability from the transport. DTLS was designed to be as similar to TLS as possible,
so this document assumes that all properties from TLS are carried over except where specified.

## Application-Specific Security Protocols

The following protocols provide application-specific security by protecting
application payloads used for specific use-cases. Unlike the protocols above,
these are not intended for generic application use.

### Secure RTP

Secure RTP (SRTP) is a profile for RTP that provides confidentiality,
message authentication, and replay protection for RTP data packets
and RTP control protocol (RTCP) packets {{?RFC3711}}.
SRTP provides a record layer only, and requires a separate handshake
protocol to provide key agreement and identity management. 

The commonly used handshake protocol for SRTP is DTLS, in the form of
DTLS-SRTP {{?RFC5764}}.  This is an extension to DTLS that negotiates
the use of SRTP as the record layer, and describes how to export keys
for use with SRTP.

ZRTP {{?RFC6189}} is an alternative key agreement and identity management
protocol for SRTP.  ZRTP Key agreement is performed using a Diffie-Hellman
key exchange that runs on the media path. This generates a shared secret
that is then used to generate the master key and salt for SRTP.

## Transport-Layer Security Protocols

The following security protocols provide protection for both application payloads and
headers that are used for transport services.

### IETF QUIC {#quic}

QUIC is a new standards-track transport protocol that runs over UDP, loosely based on Google's
original proprietary gQUIC protocol {{?I-D.ietf-quic-transport}} (See {{gquic}} for more details).
The QUIC transport layer itself provides support for data confidentiality and integrity. This requires
keys to be derived with a separate handshake protocol. A mapping for QUIC of TLS 1.3 {{?I-D.ietf-quic-tls}}
has been specified to provide this handshake.

### Google QUIC {#gquic}

Google QUIC (gQUIC) is a UDP-based multiplexed streaming protocol designed and deployed by Google
following experience from deploying SPDY, the proprietary predecessor to HTTP/2.
gQUIC was originally known as "QUIC": this document uses gQUIC to unambiguously distinguish
it from the standards-track IETF QUIC. The proprietary technical forebear of IETF QUIC, gQUIC
was originally designed with tightly-integrated security and application data transport protocols.

### tcpcrypt

Tcpcrypt {{?RFC8548}} is a lightweight extension to the TCP protocol for opportunistic encryption. Applications may
use tcpcrypt's unique session ID for further application-level authentication. Absent this authentication,
tcpcrypt is vulnerable to active attacks.

### MinimaLT

MinimaLT is a UDP-based transport security protocol designed to offer confidentiality,
mutual authentication, DoS prevention, and connection mobility {{MinimaLT}}. One major
goal of the protocol is to leverage existing protocols to obtain server-side configuration
information used to more quickly bootstrap a connection. MinimaLT uses a variant of TCP's
congestion control algorithm.

### CurveCP

CurveCP {{CurveCP}} is a UDP-based transport security protocol from Daniel J. Bernstein.
Unlike many other security protocols, it is based entirely upon public key algorithms.
CurveCP provides its own reliability for application data as part of its protocol.

## Packet Security Protocols

The following protocols provide protection for IP packets. These are generally used as tunnels,
such as for Virtual Private Networks (VPNs). Often, applications will not interact directly with these
protocols. However, applications that implement tunnels will interact directly with these protocols.

### IPsec

IKEv2 {{?RFC7296}} and ESP {{?RFC4303}} together form the modern IPsec protocol suite that encrypts
and authenticates IP packets, either for creating tunnels (tunnel-mode) or for direct transport
connections (transport-mode). This suite of protocols separates out the key generation protocol
(IKEv2) from the transport encryption protocol (ESP). Each protocol can be used independently,
but this document considers them together, since that is the most common pattern.

### WireGuard

WireGuard is an IP-layer protocol designed as an alternative to IPsec {{WireGuard}}
for certain use cases. It uses UDP to encapsulate IP datagrams between peers.
Unlike most transport security protocols, which rely on Public Key Infrastructure (PKI)
for peer authentication, WireGuard authenticates peers using pre-shared public keys
delivered out-of-band, each of which is bound to one or more IP addresses.
Moreover, as a protocol suited for VPNs, WireGuard offers no extensibility, negotiation,
or cryptographic agility.

### OpenVPN

OpenVPN {{OpenVPN}} is a commonly used protocol designed as an alternative to
IPsec. A major goal of this protocol is to provide a VPN that is simple to
configure and works over a variety of transports. OpenVPN encapsulates either
IP packets or Ethernet frames within a secure tunnel and can run over either UDP or TCP.
For key establishment, OpenVPN can use TLS as a handshake protocol or it can use pre-shared keys.

# Transport Dependencies {#transport-interface}

Across the different security protocols listed above, the primary dependency on transport
protocols is the presentation of data: either an unbounded stream of bytes, or framed
messages. Within protocols that rely on the transport for message framing, most are
built to run over transports that inherently provide framing, like UDP, but some also define
how their messages can be framed over byte-stream transports.

## Reliable Byte-Stream Transports

The following protocols all depend upon running on a transport protocol that provides
a reliable, in-order stream of bytes. This is typically TCP.

Application Payload Security Protocols:

- TLS

Transport-Layer Security Protocols:

- tcpcrypt

## Unreliable Datagram Transports

The following protocols all depend on the transport protocol to provide message framing
to encapsulate their data. These protocols are built to run using UDP, and thus do not
have any requirement for reliability. Running these protocols over a protocol that
does provide reliability will not break functionality, but may lead to multiple layers
of reliability if the security protocol is encapsulating other transport protocol traffic.

Application Payload Security Protocols:

- DTLS
- ZRTP
- SRTP

Transport-Layer Security Protocols:

- QUIC
- MinimaLT
- CurveCP

Packet Security Protocols:

- IPsec
- WireGuard
- OpenVPN

### Datagram Protocols with Defined Byte-Stream Mappings

Of the protocols listed above that depend on the transport for message framing, some
do have well-defined mappings for sending their messages over byte-stream transports
like TCP.

Application Payload Security Protocols:

- DTLS when used as a handshake protocol for SRTP {{?RFC7850}}
- ZRTP {{?RFC6189}}
- SRTP {{?RFC4571}}{{?RFC3711}}

Packet Security Protocols:

- IPsec {{?RFC8229}}

## Transport-Specific Dependencies

One protocol surveyed, tcpcrypt, has an direct dependency on a feature in the transport
that is needed for its functionality. Specific, tcpcrypt is designed to run on top of TCP, and
uses the TCP Encryption Negotiation Option (ENO) {{?RFC8547}} to negotiate its
protocol support.

QUIC, CurveCP, and MinimaLT provide both transport functionality and security functionality. They have
a dependencies on running over a framed protocol like UDP, but they add their own layers of
reliability and other transport services. Thus, an application that uses one of these protocols
cannot decouple the security from transport functionality.

# Application Interface {#application-interface}

This section describes the interface surface exposed by the security protocols described above.
We partition these interfaces into
pre-connection (configuration), connection, and post-connection interfaces, following
conventions in {{?I-D.ietf-taps-interface}} and {{?I-D.ietf-taps-arch}}.

Note that not all protocols support each interface.
The table in {{interface-protocols-table}} summarizes which protocol exposes which of the interfaces.
In the following sections, we provide abbreviations of the interface names to use in the summary table.

## Pre-Connection Interfaces

Configuration interfaces are used to configure the security protocols before a
handshake begins or the keys are negotiated.

- Identities and Private Keys (IPK): The application can provide its identities (certificates) and private keys, or
mechanisms to access these, to the security protocol to use during handshakes.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - MinimaLT
  - CurveCP
  - IPsec
  - WireGuard
  - OpenVPN

- Supported Algorithms (Key Exchange, Signatures, and Ciphersuites) (ALG):
The application can choose the algorithms that are supported for key exchange,
signatures, and ciphersuites.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - tcpcrypt
  - MinimaLT
  - IPsec
  - OpenVPN

- Extensions (EXT):
The application enables or configures extensions that are to be negotiated by
the security protocol, such as Application-Layer Protocol Negotiation (ALPN) {{?RFC7301}}.
  - TLS
  - DTLS
  - QUIC

- Session Cache Management (CM):
The application provides the ability to save and retrieve session state (such as tickets,
keying material, and server parameters) that may be used to resume the security session.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - tcpcrypt
  - MinimaLT

- Authentication Delegation (AD):
The application provides access to a separate module that will provide authentication,
using EAP for example.
  - IPsec
  - tcpcrypt

- Pre-Shared Key Import (PSKI):
Either the handshake protocol or the application directly can supply pre-shared keys for use
in encrypting (and authenticating) communication with a peer.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - ESP
  - IPsec
  - OpenVPN
  - tcpcrypt
  - MinimaLT
  - WireGuard

## Connection Interfaces

- Identity Validation (IV):
During a handshake, the security protocol will conduct identity validation of the peer.
This can call into the application to offload validation.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - MinimaLT
  - CurveCP
  - IPsec
  - WireGuard
  - OpenVPN

- Source Address Validation (SAV):
The handshake protocol may delegate validation of the remote peer that has sent
data to the transport protocol or application. This involves sending a cookie
exchange to avoid DoS attacks.
  - DTLS
  - QUIC
  - IPsec
  - WireGuard

## Post-Connection Interfaces

- Connection Termination (CT):
The security protocol may be instructed to tear down its connection and session information.
This is needed by some protocols, e.g., to prevent application data truncation attacks in
which an attacker terminates an underlying insecure connection-oriented protocol to terminate
the session.
  - TLS
  - DTLS
  - ZRTP
  - QUIC
  - tcpcrypt
  - MinimaLT
  - IPsec
  - OpenVPN

- Key Update (KU):
The handshake protocol may be instructed to update its keying material, either
by the application directly or by the record protocol sending a key expiration event.
  - TLS
  - DTLS
  - QUIC
  - tcpcrypt
  - MinimaLT
  - IPsec

- Shared Secret Export (PSKE):
The handshake protocol may provide an interface for producing shared secrets for application-specific uses.
  - TLS
  - DTLS
  - tcpcrypt
  - IPsec
  - OpenVPN
  - MinimaLT

- Key Expiration (KE):
The record protocol can signal that its keys are expiring due to reaching a time-based deadline, or a use-based
deadline (number of bytes that have been encrypted with the key). This interaction is often limited to signaling
between the record layer and the handshake layer.
  - ESP

- Mobility Events (ME):
The record protocol can be signaled that it is being migrated to another transport or interface due to
connection mobility, which may reset address and state validation and induce state changes such
as use of a new Connection Identifier (CID).
  - QUIC
  - MinimaLT
  - CurveCP
  - IPsec {{?RFC4555}}
  - WireGuard

## Summary of Interfaces Exposed by Protocols {#interface-protocols-table}

The following table summarizes which protocol exposes which interface.

|---
| Protocol  | IPK | ALG | EXT | CM | AD | PSKI | IV | SAV | CT | KU | PSKE | KE | ME |
|:----------|:---:|:---:|:---:|:--:|:--:|:----:|:--:|:---:|:--:|:--:|:----:|:--:|:--:|
| TLS       | x   | x   | x   | x  |    | x    | x  |     | x  | x  | x    |    |    |
| DTLS      | x   | x   | x   | x  |    | x    | x  | x   | x  | x  | x    |    |    |
| ZRTP      | x   | x   |     | x  |    | x    | x  |     | x  |    |      |    |    |
| QUIC      | x   | x   | x   | x  |    | x    | x  | x   | x  | x  |      |    | x  |
| tcpcrypt  |     | x   |     | x  | x  | x    |    |     | x  | x  | x    |    |    |
| MinimaLT  | x   | x   |     | x  |    | x    | x  |     | x  | x  | x    |    | x  |
| CurveCP   | x   |     |     |    |    |      | x  |     |    |    |      |    | x  |
| IPsec     | x   | x   |     |    | x  | x    | x  | x   | x  | x  | x    |    | x  |
| ESP       |     |     |     |    |    | x    |    |     |    |    |      | x  |    |
| WireGuard | x   |     |     |    |    | x    | x  | x   |    |    |      |    | x  |
| OpenVPN   | x   | x   |     |    |    | x    | x  |     | x  |    | x    |    |    |
|---

x=Interface is exposed  
(blank)=Interface is not exposed  

# IANA Considerations

This document has no request to IANA.

# Security Considerations

This document summarizes existing transport security protocols and their interfaces.
It does not propose changes to or recommend usage of reference protocols. Moreover,
no claims of security and privacy properties beyond those guaranteed by the protocols
discussed are made. For example, metadata leakage via timing side channels and traffic
analysis may compromise any protocol discussed in this survey. Applications using
Security Interfaces should take such limitations into consideration when using a particular
protocol implementation.

# Privacy Considerations

Analysis of how features improve or degrade privacy is intentionally omitted from this survey.
All security protocols surveyed generally improve privacy by reducing information leakage via
encryption. However, varying amounts of metadata remain in the clear across each
protocol. For example, client and server certificates are sent in cleartext in TLS
1.2 {{?RFC5246}}, whereas they are encrypted in TLS 1.3 {{?RFC8446}}. A survey of privacy
features, or lack thereof, for various security protocols could be addressed in a
separate document.

# Acknowledgments

The authors would like to thank Bob Bradley, Frederic Jacobs, Mirja Kühlewind,
Yannick Sierra, Brian Trammell, and Magnus Westerlund for their input and feedback
on this draft.

--- back
