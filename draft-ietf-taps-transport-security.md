---
title: A Survey of Transport Security Protocols
abbrev: transport security survey
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
    email: theresa@inet.tu-berlin.de
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
    role: editor
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

informative:
    BLAKE2:
      title: BLAKE2 -- simpler, smaller, fast as MD5
      target: https://blake2.net/blake2.pdf
      date: {DATE}
      author:
        -
          ins: J. Aumasson
        -
          ins: S. Neves
        -
          ins: Z. Wilcox-O’Hearn
        -
          ins: C. Winnerlein
    Noise:
      title: The Noise Protocol Framework
      target: http://noiseprotocol.org/noise.pdf
      date: {DATE}
      author:
        -
          ins: T. Perrin
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
    SIGMA:
      title: SIGMA -- The ‘SIGn-and-MAc’ Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols
      target: http://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf
      date: {DATE}
      author:
        -
          ins: H. Krawczyk
    CurveCP:
      title: CurveCP -- Usable security for the Internet
      target: http://curvecp.org
      date: {DATE}
      author:
        -
          ins: D. J. Bernstein
    Curve25519:
      title: Curve25519 - new Diffie-Hellman speed records
      target: https://cr.yp.to/ecdh/curve25519-20060209.pdf
      date: {DATE}
      author:
        -
          ins: D. J. Bernstein
    MinimalT:
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
Moreover, this document defines a minimal set of security features that a secure transport system should provide.

--- middle

# Introduction

Services and features provided by transport protocols have been cataloged in {{?RFC8095}}. This document
supplements that work by surveying commonly used and notable network security protocols, and
identifying the services and features a Transport Services system (a system that provides a transport API)
needs to provide in order to add transport security. It examines Transport Layer Security (TLS),
Datagram Transport Layer Security (DTLS), QUIC + TLS, tcpcrypt, Internet Key Exchange
with Encapsulating Security Protocol (IKEv2 + ESP), SRTP (with DTLS), WireGuard, CurveCP,
and MinimalT. For each protocol, this document provides a brief description, the security features it
provides, and the dependencies it has on the underlying transport. This is followed by defining the
set of transport security features shared by these protocols. The document groups these security features
into a minimal set of features, which every secure transport system should provide in addition to
the transport features described in {{?I-D.ietf-taps-minset}}, and additional optional features, which may not be
available in every secure transport system. Finally, the document distills the application and
transport interfaces provided by the transport security protocols.

Selected protocols represent a superset of functionality and features a Transport Services system may
need to support, both internally and externally (via an API) for applications {{?I-D.ietf-taps-arch}}. Ubiquitous
IETF protocols such as (D)TLS, as well as non-standard protocols such as Google QUIC,
are both included despite overlapping features. As such, this survey is not limited to protocols
developed within the scope or context of the IETF. Outside of this candidate set, protocols
that do not offer new features are omitted. For example, newer protocols such as WireGuard make
unique design choices that have important implications on applications, such as how to
best configure peer public keys and to delegate algorithm selection to the system. In contrast,
protocols such as ALTS {{ALTS}} are omitted since they do not represent features deemed unique.

Authentication-only protocols such as TCP-AO {{?RFC5925}} and IPsec AH {{?RFC4302}} are excluded
from this survey. TCP-AO adds authenticity protections to long-lived TCP connections, e.g., replay
protection  with per-packet Message Authentication Codes. (This protocol obsoletes TCP MD5 "signature"
options specified in {{?RFC2385}}.) One prime use case of TCP-AO is for protecting BGP connections.
Similarly, AH adds per-datagram authenticity and adds similar replay protection. Despite these
improvements, neither protocol sees general use and both lack critical properties important for emergent
transport security protocols: confidentiality, privacy protections, and agility. Such protocols are thus
omitted from this survey.

## Goals

[[TODO: writeme]]

## Non-Goals

[[TODO: writeme]]

# Terminology

The following terms are used throughout this document to describe the roles and interactions of transport security protocols:

- Transport Feature: a specific end-to-end feature that the transport layer provides to an application.
Examples include confidentiality, reliable delivery, ordered delivery, message-versus-stream orientation, etc.

- Transport Service: a set of Transport Features, without an association to any given framing protocol,
which provides functionality to an application.

- Transport Protocol: an implementation that provides one or more different transport services using a
specific framing and header format on the wire. A Transport Protocol services an application.

- Application: an entity that uses a transport protocol for end-to-end delivery of data across the network.
This may also be an upper layer protocol or tunnel encapsulation.

- Security Feature: a feature that a network security layer provides to applications. Examples
include authentication, encryption, key generation, session resumption, and privacy. Features may be
Mandatory or Optional for an application's implementation. Security Features extend the set of
Transport Features described in {{?RFC8095}} and provided by Transport Services implementations.

- Security Protocol: a defined network protocol that implements one or more security features. Security
protocols may be used alongside transport protocols, and in combination with other security protocols when
appropriate.

- Handshake Protocol: a protocol that enables peers to validate each other and to securely establish
shared cryptographic context.

- Record: Framed protocol messages.

- Record Protocol: a security protocol that allows data to be divided into manageable blocks and protected
using shared cryptographic context.

- Session: an ephemeral security association between applications.

- Cryptographic context: a set of cryptographic parameters, including but not necessarily limited to keys
for encryption, authentication, and session resumption, enabling authorized parties to a session to communicate securely.

- Connection: the shared state of two or more endpoints that persists across messages that are transmitted
between these endpoints. A connection is a transient participant of a session, and a session generally lasts
between connection instances.

- Peer: an endpoint application party to a session.

- Client: the peer responsible for initiating a session.

- Server: the peer responsible for responding to a session initiation.

# Transport Security Protocol Descriptions

This section contains descriptions of security protocols currently used to protect data
being sent over a network.

For each protocol, we describe its provided features and dependencies on other protocols.

## TLS

TLS (Transport Layer Security) {{?RFC8446}} is a common protocol used to establish a secure session between two endpoints. Communication
over this session "prevents eavesdropping, tampering, and message forgery." TLS consists
of a tightly coupled handshake and record protocol. The handshake protocol is used to authenticate peers,
negotiate protocol options, such as cryptographic algorithms, and derive session-specific
keying material. The record protocol is used to marshal (possibly encrypted) data from one
peer to the other. This data may contain handshake messages or raw application data.

## DTLS

DTLS (Datagram Transport Layer Security) {{?RFC6347}} is based on TLS, but differs in that
it is designed to run over unreliable datagram protocols like UDP instead of TCP.
DTLS modifies the protocol to make sure it can still provide the same security guarantees as TLS
even without reliability from the transport. DTLS was designed to be as similar to TLS as possible,
so this document assumes that all properties from TLS are carried over except where specified.

## QUIC with TLS

QUIC is a new standards-track transport protocol that runs over UDP, loosely based on Google's
original proprietary gQUIC protocol {{?I-D.ietf-quic-transport}} (See {{section-gquic}} for more details).
The QUIC transport layer itself provides support for data confidentiality and integrity. This requires
keys to be derived with a separate handshake protocol. A mapping for QUIC of TLS 1.3 {{?I-D.ietf-quic-tls}}
has been specified to provide this handshake.

### Variant: Google QUIC {#section-gquic}

Google QUIC (gQUIC) is a UDP-based multiplexed streaming protocol designed and deployed by Google
following experience from deploying SPDY, the proprietary predecessor to HTTP/2.
gQUIC was originally known as "QUIC": this document uses gQUIC to unambiguously distinguish
it from the standards-track IETF QUIC. The proprietary technical forebear of IETF QUIC, gQUIC
was originally designed with tightly-integrated security and application data transport protocols.

## IKEv2 with ESP

IKEv2 {{?RFC7296}} and ESP {{?RFC4303}} together form the modern IPsec protocol suite that encrypts
and authenticates IP packets, either for creating tunnels (tunnel-mode) or for direct transport
connections (transport-mode). This suite of protocols separates out the key generation protocol
(IKEv2) from the transport encryption protocol (ESP). Each protocol can be used independently,
but this document considers them together, since that is the most common pattern.

### Variant: ZRTP for Media Path Key Agreement

ZRTP {{?RFC6189}} is an alternative key agreement protocol for SRTP.
It uses standard SRTP to protect RTP data packets and RTCP packets, but
provides alternative key agreement and identity management protocols.

Key agreement is performed using a Diffie-Hellman key exchange that runs
on the media path. This generates a shared secret that is then used to
generate the master key and salt for SRTP.

ZRTP does not rely on a PKI or external identity management system.
Rather, it uses an ephemeral Diffie-Hellman key exchange with hash
commitment to allow detection of man-in-the-middle attacks.
This requires endpoints to display a short authentication string that the
users must read and verbally compare to validate the hashes and ensure security.
Endpoints cache some key material after the first call to use in subsequent
calls; this is mixed in with the Diffie-Hellman shared secret, so the short
authentication string need only be checked once for a given user.  This
gives key continuity properties analogous to the secure shell (ssh)
{{?RFC4253}}.

## tcpcrypt

Tcpcrypt {{?RFC8548}} is a lightweight extension to the TCP protocol for opportunistic encryption. Applications may
use tcpcrypt's unique session ID for further application-level authentication. Absent this authentication,
tcpcrypt is vulnerable to active attacks.

## WireGuard

WireGuard is a layer 3 protocol designed as an alternative to IPsec {{WireGuard}}
for certain use cases. It uses UDP to encapsulate IP datagrams between peers.
Unlike most transport security protocols, which rely on PKI for peer authentication,
WireGuard authenticates peers using pre-shared public keys delivered out-of-band, each
of which is bound to one or more IP addresses.
Moreover, as a protocol suited for VPNs, WireGuard offers no extensibility, negotiation,
or cryptographic agility.

## CurveCP

CurveCP {{CurveCP}} is a UDP-based transport security protocol from Daniel J. Bernstein.
Unlike other transport security protocols, it is based entirely upon highly efficient public
key algorithms. This removes many pitfalls associated with nonce reuse and key synchronization.

## MinimalT

MinimalT is a UDP-based transport security protocol designed to offer confidentiality,
mutual authentication, DoS prevention, and connection mobility {{MinimalT}}. One major
goal of the protocol is to leverage existing protocols to obtain server-side configuration
information used to more quickly bootstrap a connection. MinimalT uses a variant of TCP's
congestion control algorithm.

## OpenVPN

OpenVPN {{OpenVPN}} is a commonly used protocol designed as an alternative to
IPsec. A major goal of this protocol is to provide a VPN that is simple to
configure and works over a variety of transports. OpenVPN encapsulates either
IP packets or Ethernet frames within a secure tunnel and can run over UDP or
TCP.

# Transport Dependencies

- Stream
Protocols: TLS, OpenVPN, tcpcrypt

- Datagram message framing
Protocols: QUIC, DTLS, SRTP, IKEv2 and ESP, WireGuard, MinimalT, CurveCP

- Protocol-specific needs
Protocols: tcpcrypt (TCP-ENO)

# Application Interface

This section describes the interface surface exposed by the security protocols described above.
Note that not all protocols support each interface. We partition these interfaces into
pre-connection (configuration), connection, and post-connection interfaces, following
conventions in {{?I-D.ietf-taps-interface}} and {{?I-D.ietf-taps-arch}}.

## Pre-Connection Interfaces

Configuration interfaces are used to configure the security protocols before a
handshake begins or the keys are negotiated.

- Identities and Private Keys
The application can provide its identities (certificates) and private keys, or
mechanisms to access these, to the security protocol to use during handshakes.
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2, WireGuard, SRTP

- Supported Algorithms (Key Exchange, Signatures, and Ciphersuites)
The application can choose the algorithms that are supported for key exchange,
signatures, and ciphersuites.
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2, SRTP

- Extensions (Application-Layer Protocol Negotiation):
The application enables or configures extensions that are to be negotiated by
the security protocol, such as ALPN {{?RFC7301}}.
Protocols: TLS, DTLS, QUIC + TLS

- Session Cache Management
The application provides the ability to save and retrieve session state (such as tickets,
keying material, and server parameters) that may be used to resume the security session.
Protocols: TLS, DTLS, QUIC + TLS, MinimalT

- Authentication Delegation
The application provides access to a separate module that will provide authentication,
using EAP for example.
Protocols: IKEv2, SRTP

- Pre-Shared Key Import
Either the handshake protocol or the application directly can supply pre-shared keys for the
record protocol use for encryption/decryption and authentication. If the application can supply
keys directly, this is considered explicit import; if the handshake protocol traditionally
provides the keys directly, it is considered direct import; if the keys can only be shared by
the handshake, they are considered non-importable.
  - Explicit import: QUIC, ESP
  - Direct import: TLS, DTLS, MinimalT, tcpcrypt, WireGuard
  - Non-importable: CurveCP

## Connection Interfaces

- Identity Validation
During a handshake, the security protocol will conduct identity validation of the peer.
This can call into the application to offload validation.
Protocols: All (TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2, WireGuard, SRTP (DTLS))

- Source Address Validation
The handshake protocol may delegate validation of the remote peer that has sent
data to the transport protocol or application. This involves sending a cookie
exchange to avoid DoS attacks.
Protocols: QUIC + TLS, DTLS, WireGuard

## Post-Connection Interfaces

- Connection Termination
The security protocol may be instructed to tear down its connection and session information.
This is needed by some protocols to prevent application data truncation attacks.
Protocols: TLS, DTLS, QUIC, tcpcrypt, IKEv2, MinimalT

- Key Update
The handshake protocol may be instructed to update its keying material, either
by the application directly or by the record protocol sending a key expiration event.
Protocols: TLS, DTLS, QUIC, tcpcrypt, IKEv2, MinimalT

- Pre-Shared Key Export
The handshake protocol will generate one or more keys to be used for record encryption/decryption and authentication.
These may be explicitly exportable to the application, traditionally limited to direct export to the record protocol,
or inherently non-exportable because the keys must be used directly in conjunction with the record protocol.
  - Explicit export: TLS (for QUIC), tcpcrypt, IKEv2, DTLS (for SRTP)
  - Direct export: TLS, DTLS, MinimalT
  - Non-exportable: CurveCP

- Key Expiration
The record protocol can signal that its keys are expiring due to reaching a time-based deadline, or a use-based
deadline (number of bytes that have been encrypted with the key). This interaction is often limited to signaling
between the record layer and the handshake layer.
Protocols: ESP ((Editor's note: One may consider TLS/DTLS to also have this interface))

- Mobility Events
The record protocol can be signaled that it is being migrated to another transport or interface due to
connection mobility, which may reset address and state validation and induce state changes such
as use of a new Connection Identifier (CID).
Protocols: QUIC, MinimalT, CurveCP, ESP, WireGuard (roaming)

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

