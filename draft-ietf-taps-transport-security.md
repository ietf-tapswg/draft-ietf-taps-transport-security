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
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

normative:
    RFC2385:
    RFC2508:
    RFC3261:
    RFC3545:
    RFC3711:
    RFC3948:
    RFC4253:
    RFC4302:
    RFC4303:
    RFC4474:
    RFC4555:
    RFC5246:
    RFC5723:
    RFC5763:
    RFC5764:
    RFC5869:
    RFC5925:
    RFC6066:
    RFC6189:
    RFC6347:
    RFC7250:
    RFC7296:
    RFC7301:
    RFC7539:
    RFC8095:
    RFC8229:
    I-D.ietf-tls-dtls13:
    I-D.ietf-tls-dtls-connection-id:
    I-D.ietf-rtcweb-security-arch:
    I-D.ietf-tcpinc-tcpcrypt:
    I-D.ietf-tcpinc-tcpeno:
    I-D.ietf-quic-transport:
    I-D.ietf-quic-tls:
    I-D.ietf-tls-tls13:
    I-D.ietf-taps-arch:
    BLAKE2:
      title: BLAKE2 -- simpler, smaller, fast as MD5
      url: https://blake2.net/blake2.pdf
      authors:
        -
          ins: Jean-Philippe Aumasson
        -
          ins: Samuel Neves
        -
          ins: Zooko Wilcox-O’Hearn
        -
          ins: Christian Winnerlein
    Noise:
      title: The Noise Protocol Framework
      url: http://noiseprotocol.org/noise.pdf
      authors:
        -
          ins: Trevor Perrin
    WireGuard:
      title: WireGuard -- Next Generation Kernel Network Tunnel
      url: https://www.wireguard.com/papers/wireguard.pdf
      authors:
        -
          ins: Jason A. Donenfeld
    ALTS:
      title: Application Layer Transport Security
      url: https://cloud.google.com/security/encryption-in-transit/application-layer-transport-security/
      authors:
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
      url: http://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf 
      authors:
        -
          ins: H. Krawczyk
    CurveCP:
      title: CurveCP -- Usable security for the Internet
      url: http://curvecp.org
      authors:
        -
          ins: D. J. Bernstein
    Curve25519:
      title: Curve25519 - new Diffie-Hellman speed records
      url: https://cr.yp.to/ecdh/curve25519-20060209.pdf
      authors:
        -
          ins: D. J. Bernstein
    MinimalT:
      title: MinimaLT -- Minimal-latency Networking Through Better Security
      url: http://dl.acm.org/citation.cfm?id=2516737
      authors:
        -
          ins: W. Michael Petullo
          org: United States Military Academy, West Point, NY, USA
        -
          ins: Xu Zhang
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: Jon A. Solworth
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: Daniel J. Bernstein
          org: University of Illinois at Chicago, Chicago, IL, USA
        -
          ins: Tanja Lange
          org: TU Eindhoven, Eindhoven, Netherlands

--- abstract

This document provides a survey of commonly used or notable network security protocols, with a focus 
on how they interact and integrate with applications and transport protocols. Its goal is to supplement 
efforts to define and catalog transport services {{RFC8095}} by describing the interfaces required to 
add security protocols. It examines Transport Layer Security (TLS), Datagram Transport Layer Security (DTLS), 
Quick UDP Internet Connections with TLS (QUIC + TLS), MinimalT, CurveCP, tcpcrypt, Internet Key Exchange 
with Encapsulating Security Protocol (IKEv2 + ESP), SRTP (with DTLS), and WireGuard. This survey is not 
limited to protocols developed within the scope or context of the IETF, and those included represent a superset
of features a TAPS system may need to support.

--- middle

# Introduction

This document provides a survey of commonly used or notable network security protocols, with a focus 
on how they interact and integrate with applications and transport protocols.  Its goal is to supplement 
efforts to define and catalog transport services {{RFC8095}} by describing the interfaces required to 
add security protocols. It examines Transport Layer Security (TLS), Datagram Transport Layer 
Security (DTLS), Quick UDP Internet Connections with TLS (QUIC + TLS), MinimalT, CurveCP, tcpcrypt, 
Internet Key Exchange with Encapsulating Security Protocol (IKEv2 + ESP), SRTP (with DTLS), and 
WireGuard. For each protocol, this document provides a brief description, the security features it 
provides, and the dependencies it has on the underlying transport. This is followed by defining the 
set of transport security features shared by these protocols. Finally, we distill the application and 
transport interfaces provided by the transport security protocols. 

Selected protocols represent a superset of functionality and features a TAPS system may 
need to support, both internally and externally -- via an API -- for applications {{I-D.ietf-taps-arch}}. Ubiquitous
IETF protocols such as (D)TLS, as well as non-standard protocols such as Google QUIC,
are both included despite overlapping features. As such, this survey is not limited to protocols 
developed within the scope or context of the IETF. Outside of this candidate set, protocols
that do not offer new features are omitted. For example, newer protocols such as WireGuard make
unique design choices that have important implications on applications, such as how to
best configure peer public keys and to delegate algorithm selection to the system. In contrast,
protocols such as ALTS {{ALTS}} are omitted since they do not represent features deemed unique.

Also, authentication-only protocols such as TCP-AO {{RFC5925}} and IPsec AH {{RFC4302}} are excluded
from this survey. TCP-AO adds authenticity protections to long-lived TCP connections, e.g., replay 
protection  with per-packet Message Authentication Codes. (This protocol obsoletes TCP MD5 "signature" 
options specified in {{RFC2385}}.) One prime use case of TCP-AO is for protecting BGP connections. 
Similarly, AH adds per-datagram authenticity and adds similar replay protection. Despite these
improvements, neither protocol sees general use and both lack critical properties important for emergent
transport security protocols: confidentiality, privacy protections, and agility. Thus, we omit
these and related protocols from our survey.

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

- Security Feature: a specific feature that a network security layer provides to applications. Examples 
include authentication, encryption, key generation, session resumption, and privacy. Features may be 
Mandatory or Optional for an application's implementation.

- Security Protocol: a defined network protocol that implements one or more security features. Security 
protocols may be used alongside transport protocols, and in combination with other security protocols when
appropriate.

- Handshake Protocol: a protocol that enables peers to validate each other and to securely establish 
shared cryptographic context.

- Record Protocol: a security protocol that allows data to be divided into manageable blocks and protected 
using shared cryptographic context.

- Session: an ephemeral security association between applications.

- Cryptographic context: a set of cryptographic parameters, including but not necessarily limited to keys for encryption, authentication, and session resumption, enabling authorized parties to a session to communicate securely.

- Connection: the shared state of two or more endpoints that persists across messages that are transmitted 
between these endpoints. A connection is a transient participant of a session, and a session generally lasts 
between connection instances.

- Connection Mobility: a property of a connection that allows it to be multihomed or resilient across network 
interface or address changes.

- Peer: an endpoint application party to a session.

- Client: the peer responsible for initiating a session.

- Server: the peer responsible for responding to a session initiation.

# Transport Security Protocol Descriptions

This section contains descriptions of security protocols currently used to protect data 
being sent over a network.

For each protocol, we describe its provided features and dependencies on other protocols.

## TLS

TLS (Transport Layer Security) {{RFC5246}} is a common protocol used to establish a secure session between two endpoints. Communication
over this session "prevents eavesdropping, tampering, and message forgery." TLS consists
of a tightly coupled handshake and record protocol. The handshake protocol is used to authenticate peers,
negotiate protocol options, such as cryptographic algorithms, and derive session-specific
keying material. The record protocol is used to marshal (possibly encrypted) data from one
peer to the other. This data may contain handshake messages or raw application data.

### Protocol Description

TLS is the composition of a handshake and record protocol {{I-D.ietf-tls-tls13}}.
The record protocol is designed to marshal an arbitrary, in-order stream of bytes from one endpoint to the other.
It handles segmenting, compressing (when enabled), and encrypting data into discrete records. When configured
to use an authenticated encryption with associated data (AEAD) algorithm, it also handles nonce 
generation and encoding for each record. The record protocol is hidden from the client behind a 
bytestream-oriented API.

The handshake protocol serves several purposes, including: peer authentication, protocol option (key exchange
algorithm and ciphersuite) negotiation, and key derivation. Peer authentication may be mutual; however, commonly,
only the server is authenticated. X.509 certificates are commonly used in this authentication step, though
other mechanisms, such as raw public keys {{RFC7250}}, exist. The client is not authenticated unless explicitly
requested by the server with a CertificateRequest handshake message. Assuming strong cryptography, an infrastructure for trust establishment, correctly-functioning endpoints, and communication patterns free from side channels, server authentication is sufficient to establish a channel resistant to eavesdroppers.

The handshake protocol is also extensible. It allows for a variety of extensions to be included by either the client
or server. These extensions are used to specify client preferences, e.g., the application-layer protocol to be driven
with the TLS connection {{RFC7301}}, or signals to the server to aid operation, e.g., Server Name Indication (SNI) {{RFC6066}}. Various extensions also exist
to tune the parameters of the record protocol, e.g., the maximum fragment length {{RFC6066}}.

Alerts are used to convey errors and other atypical events to the endpoints. There are two classes of alerts: closure
and error alerts. A closure alert is used to signal to the other peer that the sender wishes to terminate the connection.
The sender typically follows a close alert with a TCP FIN segment to close the connection. Error alerts are used to
indicate problems with the handshake or individual records. Most errors are fatal and are followed by connection
termination. However, warning alerts may be handled at the discretion of the implementation.

Once a session is disconnected all session keying material must be destroyed, with the exception of secrets previously established expressly for purposes of session resumption.
TLS supports stateful and stateless resumption. (Here, "state" refers to bookkeeping on a per-session basis
by the server. It is assumed that the client must always store some state information in order to resume a session.)

### Protocol Features

- Forward-secure key establishment.
- Cryptographic algorithm negotiation.
- Stateful and stateless cross-connection session resumption.
- Certificate, raw public key, and pre-shared key peer authentication.
- Mandatory server authentication, optional client authentication.
- Byte stream confidentiality and integrity.
- Segment replay prevention.
- Extensibility via well-defined extensions.
- Application-layer feature negotiation.
- 0-RTT data support (starting with TLS 1.3).
- Optional length-hiding padding (starting with TLS 1.3).

### Protocol Dependencies

- TCP for in-order, reliable transport.
- (Optionally) A PKI trust store for certificate validation.

## DTLS

DTLS (Datagram Transport Layer Security) {{RFC6347}} is based on TLS, but differs in that
it is designed to run over UDP instead of TCP. Since UDP does not guarantee datagram
ordering or reliability, DTLS modifies the protocol to make sure it can still provide
the same security guarantees as TLS. DTLS was designed to be as close to TLS as possible,
so this document will assume that all properties from TLS are carried over except where specified.

### Protocol Description

DTLS is modified from TLS to operate with the possibility of packet loss, reordering, and duplication that may occur when operating over UDP. To enable out-of-order delivery of application data, the DTLS record protocol itself has no inter-record dependencies. However, as the handshake requires reliability, each handshake message is assigned an explicit sequence number to enable retransmissions of lost packets and in-order processing by the receiver. Handshake message loss is remedied by sender retransmission after a configurable period in which the expected response has not yet been received.

As the DTLS handshake protocol runs atop the record protocol, to account for long handshake messages that cannot fit within a single record, DTLS supports fragmentation and subsequent reconstruction of handshake messages across records. The receiver must reassemble records before processing.

DTLS relies on unique UDP 4-tuples to identify connections. Since all application-layer data is encrypted, 
demultiplexing over the same 4-tuple requires the use of a connection identifier extension {{I-D.ietf-tls-dtls-connection-id}} 
to permit identification of the correct connection-specific cryptographic context without the use of trial decryption. 
(Note that this extension is only supported in DTLS 1.2 and 1.3 {{I-D.ietf-tls-dtls13}.)

Since datagrams can be replayed, DTLS provides optional anti-replay detection based on a window of acceptable sequence numbers {{RFC6347}}.

### Protocol Features

- Datagram replay protection.
- Datagram confidentiality and integrity.
- Cryptographic handshake message reliability.
- Out-of-order datagram receipt.
- Cookie-based DoS mitigation.

See also the features from TLS.

### Protocol Dependencies

- Since DTLS runs over an unreliable, unordered datagram transport, it does not require any reliability features.
- The DTLS record protocol explicitly encodes record lengths, so although it runs over a datagram transport, it does not rely on the transport protocol's framing beyond requiring transport-level reconstruction of datagrams fragmented over packets. 
(Note: DTLS 1.3 short header records omit the explicit length field.)
- UDP 4-tuple uniqueness, or the connection identifier extension, for demultiplexing.
- Path MTU discovery.

## (IETF) QUIC with TLS

QUIC (Quick UDP Internet Connections) is a new standards-track transport protocol that runs over 
UDP, loosely based on Google's original proprietary gQUIC protocol {{I-D.ietf-quic-transport}}. 
(See {{section-gquic}} for more details.) The QUIC transport layer itself provides support for data 
confidentiality and integrity. This requires keys to be derived with a separate handshake protocol.
A mapping for QUIC over TLS 1.3 {{I-D.ietf-quic-tls}} has been specified to provide this handshake.

### Protocol Description

As QUIC relies on TLS to secure its transport functions, it creates specific integration points
between its security and transport functions:

- Starting the handshake to generate keys and provide authentication (and providing the transport for the handshake).
- Client address validation.
- Key ready events from TLS to notify the QUIC transport.
- Exporting secrets from TLS to the QUIC transport.

The QUIC transport layer support multiple streams over a single connection. The first
stream is reserved specifically for a TLS connection. The TLS handshake, along with
further records, are sent over this stream. This TLS connection follows the TLS standards
and inherits the security properties of TLS. The handshake generates keys, which are
then exported to the rest of the QUIC connection, and are used to protect the rest of the streams.

Initial QUIC messages (packets) are encrypted using "fixed" keys derived from the QUIC version and 
public packet information (Connection ID). Packets are later encrypted using keys derived
from the TLS traffic secret upon handshake completion. The TLS 1.3
handshake for QUIC is used in either a single-RTT mode or a fast-open zero-RTT mode. When
zero-RTT handshakes are possible, the encryption first transitions to use the zero-RTT keys
before using single-RTT handshake keys after the next TLS flight.

### Protocol Features

- Cookie-based DoS mitigation.

See also the properties of TLS.

### Protocol Dependencies

- QUIC transport relies on UDP.
- QUIC transport relies on TLS 1.3 for authentication and initial key derivation.
- TLS within QUIC relies on a reliable stream abstraction for its handshake.

### Variant: Google QUIC {#section-gquic}

Google QUIC (gQUIC) is a UDP-based multiplexed streaming protocol designed and deployed by Google 
following experience from deploying SPDY, the proprietary predecessor to HTTP/2.
gQUIC was originally known as "QUIC": this document uses gQUIC to unambiguously distinguish 
it from the standards-track IETF QUIC. The proprietary technical forebear of IETF QUIC, gQUIC 
was originally designed with tightly-integrated security and application data transport protocols.

## IKEv2 with ESP

IKEv2 {{RFC7296}} and ESP {{RFC4303}} together form the modern IPsec protocol suite that encrypts and authenticates IP packets, either as for creating tunnels (tunnel-mode) or for direct transport connections (transport-mode). This suite of protocols separates out the key generation protocol (IKEv2) from the transport encryption protocol (ESP). Each protocol can be used independently, but this document considers them together, since that is the most common pattern.

### Protocol descriptions

#### IKEv2

IKEv2 is a control protocol that runs on UDP port 500. Its primary goal is to generate keys for Security Associations (SAs). 
An SA contains shared (cryptographic) information used for establishing other SAs or keying ESP; See {{ESP}}.
IKEv2 first uses a Diffie-Hellman key exchange to generate keys for the "IKE SA", which is a set of keys used to encrypt further IKEv2 messages. It then goes through a phase of authentication in which both peers present blobs signed by a shared secret or private key, after which another set of keys is derived, referred to as the "Child SA". These Child SA keys are used by ESP.

IKEv2 negotiates which protocols are acceptable to each peer for both the IKE and Child SAs using "Proposals". Each proposal may contain an encryption algorithm, an authentication algorithm, a Diffie-Hellman group, and (for IKE SAs only) a pseudorandom function algorithm. Each peer may support multiple proposals, and the most preferred mutually supported proposal is chosen during the handshake.

The authentication phase of IKEv2 may use Shared Secrets, Certificates, Digital Signatures, or an EAP (Extensible Authentication Protocol) method. At a minimum, IKEv2 takes two round trips to set up both an IKE SA and a Child SA. If EAP is used, this exchange may be expanded.

Any SA used by IKEv2 can be rekeyed upon expiration, which is usually based either on time or number of bytes encrypted.

There is an extension to IKEv2 that allows session resumption {{RFC5723}}.

MOBIKE is a Mobility and Multihoming extension to IKEv2 that allows a set of Security Associations to migrate over different addresses and interfaces {{RFC4555}}.

When UDP is not available or well-supported on a network, IKEv2 may be encapsulated in TCP {{RFC8229}}.

#### ESP {#ESP}
 
ESP is a protocol that encrypts and authenticates IPv4 and IPv6 packets. The keys used for both encryption and authentication can be derived from an IKEv2 exchange. ESP Security Associations come as pairs, one for each direction between two peers. Each SA is identified by a Security Parameter Index (SPI), which is marked on each encrypted ESP packet.

ESP packets include the SPI, a sequence number, an optional Initialization Vector (IV), payload data, padding, a length and next header field, and an Integrity Check Value.

From {{RFC4303}}, "ESP is used to provide confidentiality, data origin authentication, connectionless integrity, an anti-replay service (a form of partial sequence integrity), and limited traffic flow confidentiality."

Since ESP operates on IP packets, it is not directly tied to the transport protocols it encrypts. This means it requires little or no change from transports in order to provide security.

ESP packets may be sent directly over IP, but where network conditions warrant (e.g., when a NAT is present or when a firewall blocks such packets) they may be encapsulated in UDP {{RFC3948}} or TCP {{RFC8229}}.

### Protocol features

#### IKEv2

- Forward-secure key establishment.
- Mutual authentication.
- Cryptographic algorithm negotiation.
- Datagram confidentiality and integrity.
- Session resumption {{RFC5723}}.
- Connection mobility.
- Cookie-based DoS mitigation.
- Certificate, raw public key, pre-shared key, and EAP peer authentication.

#### ESP

- Datagram confidentiality and integrity.
- Connectionless integrity.
- Datagram replay protection.

### Protocol dependencies

#### IKEv2

- Availability of UDP to negotiate, or implementation support for TCP-encapsulation.
- Some EAP authentication types require accessing a hardware device, such as a SIM card; or interacting with a user, such as password prompting.

#### ESP

- Since ESP is below transport protocols, it does not have any dependencies on the transports themselves, other than on UDP or TCP where encapsulation is employed.

## Secure RTP (with DTLS)

Secure RTP (SRTP) is a profile for RTP that provides confidentiality, message
authentication, and replay protection for RTP data packets and RTP control
protocol (RTCP) packets {{RFC3711}}.

### Protocol description

SRTP adds confidentiality and optional integrity protection to RTP data packets,
and adds confidentially and mandatory integrity protection to RTCP packets.
For RTP data packets, this is done by encrypting the payload section of the packet
and optionally appending an authentication tag (MAC) as a packet trailer, with the RTP
header authenticated but not encrypted (the RTP header was left unencrypted
to enable RTP header compression {{RFC2508}} {{RFC3545}}). For RTCP packets, the first packet
in the compound RTCP packet is partially encrypted, leaving the first eight octets of
the header as clear-text to allow identification of the packet as RTCP, while the remainder
of the compound packet is fully encrypted. The entire RTCP packet is then authenticated
by appending a MAC as packet trailer.

Packets are encrypted using session keys, which
are ultimately derived from a master key and an additional master salt and session salt.
SRTP packets carry a 2-byte sequence number to partially identify the unique packet
index. SRTP peers maintain a separate roll-over counter (ROC) for RTP data packets that is
incremented whenever the sequence number wraps. The sequence number and ROC together 
determine the packet index. RTCP packets have a similar, yet differently named, field
called the RTCP index which serves the same purpose.

Numerous encryption modes are supported. For popular modes of operation, e.g., AES-CTR, 
the (unique) initialization vector (IV) used for each encryption mode is a function of 
the RTP SSRC (synchronization source), packet index, and session "salting key".

SRTP offers replay detection by keeping a replay list of already seen and processed packet indices. 
If a packet arrives with an index that matches one in the replay list, it is silently discarded.

DTLS {{RFC5764}} is commonly used to perform mutual authentication and key
agreement for SRTP {{RFC5763}}.
Peers use DTLS to perform mutual certificate-based authentication on the
media path, and to generate the SRTP master key.
Peer certificates can be issued and signed by a certificate authority.
Alternatively, certificates used in the DTLS exchange can be self-signed.
If they are self-signed, certificate fingerprints are included in the signalling
exchange (e.g., in SIP or WebRTC), and used to bind the DTLS key exchange in
the media plane to the signaling plane.
The combination of a mutually authenticated DTLS key exchange on the media
path and a fingerprint sent in the signalling channel protects against
active attacks on the media, provided the signalling can be trusted.
Signalling needs to be protected as described in, for example, SIP
{{RFC3261}} Authenticated Identity Management {{RFC4474}} or the WebRTC
security architecture {{I-D.ietf-rtcweb-security-arch}}, to provide
complete system security.

### Protocol features

- Forward-secure key establishment.
- Cryptographic algorithm negotiation.
- Partial datagram confidentiality, protecting media payloads and control packets but not data packet headers.
- Optional authentication of data packets.
- Mandatory authentication of control packets.
- Optional replay protection with tunable replay windows.
- Out-of-order datagram receipt.
- Mutual authentication {{RFC5764}}.

### Protocol dependencies

- External key derivation and management protocol, e.g., DTLS {{RFC5763}}.
- External identity management protocol, e.g., SIP Authenticated Identity Management
  {{RFC4474}}, WebRTC Security Architecture {{I-D.ietf-rtcweb-security-arch}}.

### Variant: ZRTP for Media Path Key Agreement

ZRTP {{RFC6189}} is an alternative key agreement protocol for SRTP. 
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
{{RFC4253}}.

## tcpcrypt

Tcpcrypt is a lightweight extension to the TCP protocol to enable opportunistic encryption with hooks 
available to the application layer for implementation of endpoint authentication.

### Protocol Description

Tcpcrypt extends TCP to enable opportunistic encryption between the two ends of a TCP connection {{I-D.ietf-tcpinc-tcpcrypt}}.
It is a family of TCP encryption protocols (TEP), distinguished by key exchange algorithm.
The use of a TEP is negotiated with a TCP option during the initial TCP handshake via the mechanism described by TCP Encryption Negotiation Option (ENO) {{I-D.ietf-tcpinc-tcpeno}}.
In the case of initial session establishment, once a tcpcrypt TEP has been negotiated the key exchange occurs within the data segments of the first few packets exchanged after the handshake completes. The initiator of a connection sends a list of supported AEAD algorithms, a random nonce, and an ephemeral public key share.
The responder typically chooses a mutually-supported AEAD algorithm and replies with this choice, its own nonce, and ephemeral key share.
An initial shared secret is derived from the ENO handshake, the tcpcrypt handshake, and the initial keying material resulting from the key exchange. The traffic encryption keys on the initial connection are derived from the shared secret.
Connections can be re-keyed before the natural AEAD limit for a single set of traffic encryption keys is reached.

Each tcpcrypt session is associated with a ladder of resumption IDs, each derived from the respective entry in a ladder of shared secrets.
These resumption IDs can be used to negotiate a stateful resumption of the session in a subsequent connection, resulting in use of a new shared secret and traffic encryption keys without requiring a new key exchange.
Willingness to resume a session is signaled via the ENO option during the TCP handshake.
Given the length constraints imposed by TCP options, unlike stateless resumption mechanisms (such as that provided by session tickets in TLS) resumption in tcpcrypt requires the maintenance of state on the server, and so successful resumption across a pool of servers implies shared state.

Owing to middlebox ossification issues, tcpcrypt only protects the payload portion of a TCP packet.
It does not encrypt any header information, such as the TCP sequence number.

Tcpcrypt exposes a universally-unique connection-specific session ID to the application, suitable for application-level endpoint authentication either in-band or out-of-band.

### Protocol Features

- Forward-secure key establishment.
- Byte stream confidentiality and integrity.
- Stateful cross-connection session resumption.
- Connection re-keying.
- Application authentication delegation.

### Protocol Dependencies

- TCP
- TCP Encryption Negotiation Option (ENO)

## WireGuard

WireGuard is a layer 3 protocol designed to complement or replace IPsec {{WireGuard}}.
Unlike most transport security protocols, which rely on PKI for peer authentication, 
WireGuard authenticates peers using pre-shared public keys delivered out-of-band, each 
of which is bound to one or more IP addresses. 
Moreover, as a protocol suited for VPNs, WireGuard offers no extensibility, negotiation, 
or cryptographic agility. 

### Protocol description

WireGuard is a simple VPN protocol that binds a pre-shared public key to one or more
IP addresses. Users configure WireGuard by associating peer public keys with IP addresses. 
These mappings are stored in a CryptoKey Routing Table. (See Section 2 of {{WireGuard}}
for more details and sample configurations.) These keys are used upon WireGuard packet 
transmission and reception. For example, upon receipt of a Handshake Initiation message,
receivers use the static public key in their CryptoKey routing table to perform necessary
cryptographic computations.

WireGuard builds on Noise {{Noise}} for 1-RTT key exchange with identity hiding. The handshake
hides peer identities as per the SIGMA construction {{SIGMA}}. As a consequence of using Noise, 
WireGuard comes with a fixed set of cryptographic algorithms:

- x25519 {{Curve25519}} and HKDF {{RFC5869}} for ECDH and key derivation.
- ChaCha20+Poly1305 {{RFC7539}} for packet authenticated encryption.
- BLAKE2s {{BLAKE2}} for hashing.

There is no cryptographic agility. If weaknesses are found in any of
these algorithms, new message types using new algorithms must be introduced.

WireGuard is designed to be entirely stateless, modulo the CryptoKey routing table, which has size
linear with the number of trusted peers. If a WireGuard receiver is under heavy load and cannot process
a packet, e.g., cannot spare CPU cycles for point multiplication, it can reply with a cookie similar
to DTLS and IKEv2. This cookie only proves IP address ownership. Any rate limiting scheme can be applied
to packets coming from non-spoofed addresses.

### Protocol features

- Forward-secure key establishment.
- Public-key and PSK-based peer authentication.
- Mutual authentication.
- (Stateful, timestamp-based) replay prevention.
- Cookie-based DoS mitigation.

### Protocol dependencies

- Datagram transport.
- Out-of-band key distribution and management.

## MinimalT

MinimalT is a UDP-based transport security protocol designed to offer confidentiality, mutual authentication, DoS prevention, and connection
mobility {{MinimalT}}. One major goal of the protocol is to leverage existing protocols to obtain server-side configuration information used to
more quickly bootstrap a connection. MinimalT uses a variant of TCP's congestion control algorithm.

### Protocol Description

MinimalT is a secure transport protocol built on top of a widespread directory service. Clients and servers interact with local directory
services to (a) resolve server information and (b) public ephemeral state information, respectively. Clients connect to a local
resolver once at boot time. Through this resolver they recover the IP address(es) and public key(s) of each server to which
they want to connect.

Connections are instances of user-authenticated, mobile sessions between two endpoints. Connections run within tunnels between hosts. A tunnel
is a server-authenticated container that multiplexes multiple connections between the same hosts. All connections in a tunnel share the
same transport state machine and encryption. Each tunnel has a dedicated control connection used to configure and manage the tunnel over time.
Moreover, since tunnels are independent of the network address information, they may be reused as both ends of the tunnel move about the network.
This does however imply that the connection establishment and packet encryption mechanisms are coupled.

Before a client connects to a remote service, it must first establish a tunnel to the host providing or offering the service. Tunnels are established
in 1-RTT using an ephemeral key obtained from the directory service. Tunnel initiators provide their own ephemeral key and, optionally, a
DoS puzzle solution such that the recipient (server) can verify the authenticity of the request and derive a shared secret. Within a tunnel,
new connections to services may be established.

### Protocol Features

- Forward-secure key establishment.
- 0-RTT forward secrecy for new connections.
- Puzzle-based DoS mitigation. 
- (Tunnel-based) connection migration.

Additional (orthogonal) transport features include: connection multiplexing between hosts across shared tunnels, and congestion control state is shared across connections between the same host pairs.

### Protocol Dependencies

- A DNS-like resolution service to obtain location information (an IP address) and ephemeral keys.
- A PKI trust store for certificate validation.

## CurveCP

CurveCP {{CurveCP}} is a UDP-based transport security protocol from Daniel J. Bernstein.
Unlike other transport security protocols, it is based entirely upon highly efficient public
key algorithms. This removes many pitfalls associated with nonce reuse and key synchronization.

### Protocol Description

CurveCP is a UDP-based transport security protocol. It is built on three principal features: exclusive use of public key authenticated
encryption of packets, server-chosen cookies to prohibit memory and computation DoS at the server, and connection mobility with a
client-chosen ephemeral identifier.

There are two rounds in CurveCP. In the first round, the client sends its first initialization packet to the server, carrying its (possibly fresh)
ephemeral public key C', with zero-padding encrypted under the server's long-term public key. The server replies with a cookie and its own ephemeral
key S' and a cookie that is to be used by the client. Upon receipt, the client then generates its second initialization packet carrying: the
ephemeral key C', cookie, and an encryption of C', the server's domain name, and, optionally, some message data. The server verifies the cookie
and the encrypted payload and, if valid, proceeds to send data in return. At this point, the connection is established and the two
parties can communicate.

The use of only public-key encryption and authentication, or "boxing", is done to simplify problems that come with symmetric key management
and synchronization. For example, it allows the sender of a message to be in complete control of each message's nonce. It does not require
either end to share secret keying material.
Furthermore, it allows connections (or sessions) to be associated with unique ephemeral public keys as a mechanism for enabling forward secrecy given the risk of long-term private key compromise.

The client and server do not perform a standard key exchange. Instead, in the initial exchange of packets, each party provides its
own ephemeral key to the other end. The client can choose a new ephemeral key for every new connection. However, the server must rotate
these keys on a slower basis. Otherwise, it would be trivial for an attacker to force the server to create and store ephemeral keys
with a fake client initialization packet.

Unlike TCP, the server employs cookies to enable source validation. After receiving the client's initial packet, encrypted under the server's
long-term public key, the server generates and returns a stateless cookie that must be echoed back in the client's following message.
This cookie is encrypted under the client's ephemeral public key.
This stateless technique prevents attackers from hijacking client initialization packets to obtain cookie values to flood clients. (A client
would detect the duplicate cookies and reject the flooded packets.) Similarly, replaying the client's second packet, carrying the cookie,
will be detected by the server.

CurveCP supports a weak form of client authentication. Clients are permitted to send their long-term public keys in the second initialization
packet. A server can verify this public key and, if untrusted, drop the connection and subsequent data.

Unlike some other protocols, CurveCP data packets leave only the ephemeral public key, the connection ID, and the per-message nonce
in the clear. Everything else is encrypted.

### Protocol Features

- Datagram confidentiality and integrity (via public key encryption).
- 1-RTT session bootstrapping.
- Connection mobility (based on a client-chosen ephemeral identifier).
- Optional length-hiding and anti-amplification padding.

### Protocol Dependencies

- An unreliable transport protocol such as UDP.

# Security Features and Transport Dependencies

There exists a common set of features shared across the transport protocols surveyed in this document.
Mandatory features constitute a baseline of functionality that an application may assume for any TAPS
implementation. Optional features by contrast may vary from implementation to implementation, and so 
an application cannot simply assume they are available. Applications learn of and use optional features by 
querying for their presence and support. Optional features may not be implemented, or may be disabled if 
their presence impacts transport services or if a necessary transport service is unavailable.

## Mandatory Features

- Segment or datagram encryption and authentication: Transit data must be protected with an authenticated 
encryption algorithm.

- Forward-secure key establishment: Negotiated keying material must come from an authenticated,
forward-secure key exchange protocol.

- Public-key (raw or certificate) based authentication: Authentication based on public key signatures is 
commonplace for many transport security protocols.

- Responder authentication: The endpoint (receiver) of a new connection must be authenticated before any
data is sent to said party.

- Pre-shared key support: A security protocol must be able to use a pre-shared key established 
out-of-band or from a prior session to encrypt individual messages, packets, or datagrams.

## Optional Features

- Cryptographic algorithm negotiation: Transport security protocols should permit applications to configure 
supported or enabled cryptographic algorithms.
  - Transport dependency: None.
  - Application dependency: Application awareness of supported or desired algorithms.

- Application authentication delegation: Some protocols may completely defer endpoint authentication to applications,
e.g., to reduce online protocol complexity.
  - Transport dependency: None.
  - Application dependency: Application opt-in and policy for endpoint authentication

- Mutual authentication: Transport security protocols should allow each endpoint to authenticate the other if 
required by the application.
  - Transport dependency: None.
  - Application dependency: Mutual authentication required for application support.

- DoS mitigation: Transport security protocols may need to support volumetric DoS prevention via, e.g., 
cookies or initiator-side puzzles.
  - Transport dependency: None.
  - Application dependency: None.

- Connection mobility: Sessions should not be bound to a network connection (or 5-tuple). This allows cryptographic
key material and other state information to be reused in the event of a connection change. Examples of this include
a NAT rebinding that occurs without a client's knowledge.
  - Transport dependency: Connections are unreliable or can change due to unpredictable network events, e.g.,
  NAT re-bindings.
  - Application dependency: None.

- Source validation: Source validation must be provided to mitigate server-targeted DoS attacks. This can
be done with puzzles or cookies.
  - Transport dependency: Packets may arrive as datagrams instead of streams from unauthenticated sources.
  - Application dependency: None.

- Application-layer feature negotiation: The type of application using a transport security protocol often requires
features configured at the connection establishment layer, e.g., ALPN {{RFC7301}}. Moreover, application-layer 
features may often be used to offload the session to another server which can better handle the request. (The TLS SNI 
is one example of such a feature.) As such, transport security protocols should provide a generic mechanism to allow 
for such application-specific features and options to be configured or otherwise negotiated.
  - Transport dependency: None.
  - Application dependency: Specification of application-layer features or functionality.

- Configuration extensions: The protocol negotiation should be extensible with addition of new configuration options.
  - Transport dependency: None.
  - Application dependency: Specification of application-specific extensions.

- Session caching (and management): Sessions should be cacheable to enable reuse and amortize the cost 
of performing session establishment handshakes.
  - Transport dependency: None.
  - Application dependency: None.

- Length-hiding padding: Applications may wish to defer traffic padding to the security protocol to deter traffic
analysis attacks.
  - Transport dependency: None.
  - Application dependency: Knowledge of desired padding policies.

# Transport Security Protocol Interfaces

This section describes the interface surface exposed by the security protocols described above. 
Note that not all protocols support each interface. We partition these interfaces into 
pre-connection (configuration), connection, and post-connection interfaces. 

## Pre-Connection Interfaces

Configuration interfaces are used to configure the security protocols before a
handshake begins or the keys are negotiated.

- Identity and Private Keys  
The application can provide its identities (certificates) and private keys, or
mechanisms to access these, to the security protocol to use during handshakes.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2, WireGuard, SRTP

- Supported Algorithms (Key Exchange, Signatures, and Ciphersuites)  
The application can choose the algorithms that are supported for key exchange,
signatures, and ciphersuites.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2, SRTP

- Session Cache Management
The application provides the ability to save and retrieve session state (such as tickets,
keying material, and server parameters) that may be used to resume the security session.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT

- Authentication Delegation  
The application provides access to a separate module that will provide authentication,
using EAP for example.  
Protocols: IKEv2, SRTP

- Pre-Shared Key Import  
Either the handshake protocol or the application directly can supply pre-shared keys for the record protocol use for encryption/decryption and authentication. If the application can supply keys directly, this is considered explicit import; if the handshake protocol traditionally provides the keys directly, it is considered direct import; if the keys can only be shared by the handshake, they are considered non-importable.
  - Explict import: QUIC, ESP
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
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2

- Key Update  
The handshake protocol may be instructed to update its keying material, either
by the application directly or by the record protocol sending a key expiration event.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2

- Pre-Shared Key Export
The handshake protocol will generate one or more keys to be used for record encryption/decryption and authentication. These may be explicitly exportable to the application, traditionally limited to direct export to the record protocol, or inherently non-exportable because the keys must be used directly in conjunction with the record protocol.  
  - Explicit export: TLS (for QUIC), tcpcrypt, IKEv2, DTLS (for SRTP)
  - Direct export: TLS, DTLS, MinimalT
  - Non-exportable: CurveCP

- Key Expiration  
The record protocol can signal that its keys are expiring due to reaching a time-based deadline, or a use-based deadline (number of bytes that have been encrypted with the key). This interaction is often limited to signaling between the record layer and the handshake layer.  
Protocols: ESP ((Editor's note: One may consider TLS/DTLS to also have this interface))

- Connection mobility  
The record protocol can be signaled that it is being migrated to another transport or interface due to 
connection mobility, which may reset address and state validation.  
Protocols: QUIC, MinimalT, CurveCP, ESP, WireGuard (roaming)

# IANA Considerations

This document has no request to IANA.

# Security Considerations

This document summarizes existing transport security protocols and their interfaces. 
It does not propose changes to or recommend usage of reference protocols. Moreover,
no claims of security and privacy properties beyond those guaranteed by the protocols 
discussed are made. For example, metadata leakage via timing side channels and traffic
analysis may compromise any protocol discussed in this survey. Applications using
Security Interfaces SHOULD take such limitations into consideration when using a particular
protocol implementation.

# Acknowledgments

The authors would like to thank Mirja Kühlewind, Brian Trammell, Yannick Sierra,
Frederic Jacobs, and Bob Bradley for their input and feedback on earlier versions
of this draft.
