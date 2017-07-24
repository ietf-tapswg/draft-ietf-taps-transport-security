---
title: A Survey of Transport Security Protocols
abbrev: transport security survey
docname: draft-pauly-taps-transport-security-latest
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
    street: 1 Infinite Loop
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple Inc.
    street: 1 Infinite Loop
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

normative:
    RFC4303:
    RFC4555:
    RFC5246:
    RFC5723:
    RFC6066:
    RFC6347:
    RFC7250:
    RFC7296:
    RFC7301:
    RFC8095:
    I-D.ietf-tcpinc-tcpcrypt:
    I-D.ietf-tcpinc-tcpeno:
    I-D.ietf-quic-transport:
    I-D.ietf-quic-tls:
    I-D.ietf-tls-tls13:
    I-D.ietf-ipsecme-tcp-encaps:
    CurveCP:
        title: CurveCP -- Usable security for the Internet
        url: http://curvecp.org
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

This document provides a survey of commonly used or notable network security protocols, with a focus on how they interact and integrate with applications and transport protocols. Its goal is to supplement efforts to define and catalog transport services {{RFC8095}} by describing the interfaces required to add security protocols. It examines Transport Layer Security (TLS), Datagram Transport Layer Security (DTLS), Quick UDP Internet Connections with TLS (QUIC + TLS), MinimalT, CurveCP, tcpcrypt, and Internet Key Exchange with Encapsulating Security Protocol (IKEv2 + ESP). This survey is not limited to protocols developed within the scope or context of the IETF.

--- middle

# Introduction

This document provides a survey of commonly used or notable network security protocols, with a focus on how they interact and integrate with applications and transport protocols.  Its goal is to supplement efforts to define and catalog transport services {{RFC8095}} by describing the interfaces required to add security protocols. It examines Transport Layer Security (TLS), Datagram Transport Layer Security (DTLS), Quick UDP Internet Connections with TLS (QUIC + TLS), MinimalT, CurveCP, tcpcrypt, Internet Key Exchange with Encapsulating Security Protocol (IKEv2 + ESP), SRTP, and WireGuard. This survey is not limited to protocols developed within the scope or context of the IETF.

For each protocol, this document provides a brief description, the security features it provides, and the dependencies it has on the underlying transport. This is followed by defining the set of transport security features shared by these protocols. Finally, we distill the application and transport interfaces provided by the transport security protocols.

# Terminology

The following terms are used throughout this document to describe the roles and interactions of transport security protocols:

- Transport Feature: a specific end-to-end feature that the transport layer provides to an application.  Examples include confidentiality, reliable delivery, ordered delivery, message-versus-stream orientation, etc.

- Transport Service: a set of Transport Features, without an association to any given framing protocol, which provides a functionality to an application.

- Transport Protocol: an implementation that provides one or more different transport services using a specific framing and header format on the wire. A Transport Protocol services an application.

- Application: an entity that uses a transport protocol for end-to-end delivery of data across the network (this may also be an upper layer protocol or tunnel encapsulation).

- Security Feature: a specific feature that a network security layer provides to applications. Examples include authentication, encryption, key generation, session resumption, and privacy. A feature may be considered to be Mandatory or Optional to an application's implementation.

- Security Protocol: a defined network protocol that implements one or more security features. Security protocols may be used alongside transport protocols, and in combination with one another when appropriate.

- Handshake Protocol: a security protocol that performs a handshake to validate peers and establish a shared cryptographic key.

- Record Protocol: a security protocol that allows data to be encrypted in records or datagrams based on a shared cryptographic key.

- Session: an ephemeral security association between applications.

- Connection: the shared state of two or more endpoints that persists across messages that are transmitted between these endpoints. A connection is a transient participant of a session, and a session generally lasts between connection instances.

- Connection Mobility: a property of a connection that allows it to be multihomed or resilient across network interface or address changes.

- Peer: an endpoint application party to a session.

- Client: the peer responsible for initiating a session.

- Server: the peer responsible for responding to a session initiation.

# Transport Security Protocol Descriptions

This section contains descriptions of security protocols that currently used to protect data being sent over a network.

For each protocol, we describe the features it provides and its dependencies on other protocols.

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
to use an AEAD algorithm, it also handles nonce generation and encoding for each record. The record protocol is
hidden from the client behind a byte stream-oriented API.

The handshake protocol serves several purposes, including: peer authentication, protocol option (key exchange
algorithm and ciphersuite) negotiation, and key derivation. Peer authentication may be mutual. However, commonly,
only the server is authenticated. X.509 certificates are commonly used in this authentication step, though
other mechanisms, such as raw public keys {{RFC7250}}, exist. The client is not authenticated unless explicitly
requested by the server with a CertificateRequest handshake message.

The handshake protocol is also extensible. It allows for a variety of extensions to be included by either the client
or server. These extensions are used to specify client preferences, e.g., the application-layer protocol to be driven
with the TLS connection {{RFC7301}}, or signals to the server to aid operation, e.g., the server name {{RFC6066}}. Various extensions also exist
to tune the parameters of the record protocol, e.g., the maximum fragment length {{RFC6066}}.

Alerts are used to convey errors and other atypical events to the endpoints. There are two classes of alerts: closure
and error alerts. A closure alert is used to signal to the other peer that the sender wishes to terminate the connection.
The sender typically follows a close alert with a TCP FIN segment to close the connection. Error alerts are used to
indicate problems with the handshake or individual records. Most errors are fatal and are followed by connection
termination. However, warning alerts may be handled at the discretion of each respective implementation.

Once a session is disconnected all session keying material must be torn down, unless resumption information was previously
negotiated. TLS supports stateful and stateless resumption. (Here, the state refers to the information requirements
for the server. It is assumed that the client must always store some state information in order to resume a session.)

### Protocol Features

- Key exchange and ciphersuite algorithm negotiation.
- Stateful and stateless session resumption.
- Certificate- and raw public-key-based authentication.
- Mutual client and server authentication.
- Byte stream confidentiality and integrity.
- Extensibility via well-defined extensions.
- 0-RTT data support (in TLS 1.3 only).
- Application-layer protocol negotiation.
- Transparent data segmentation.

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

DTLS is modified from TLS to account for packet loss and reordering that occur when operating over a datagram-based transport, i.e., UDP. Each message is assigned an explicit sequence number to be used to reorder on the receiving end. This removes the inter-record dependency and allows each record to be decrypt in isolation of the rest. However, DTLS does not deviate from TLS in that in still provides in-order delivery of data to the application.

With respect to packet loss, if one peer has sent a handshake message and has not yet received its expected response, it will retransmit the handshake message after a configurable timeout.

To account for long records that cannot fit within a single UDP datagram, DTLS supports fragmentation of records across datagrams, keeping track of fragment offsets and lengths in each datagram. The receiving peer must re-assemble records before decrypting.

DTLS relies on UDP's port numbers to allow peers with multiple DTLS sessions between them to demultiplex 'streams' of encrypted packets that share a single TLS session.

Since datagrams may be replayed, DTLS provides anti-replay detection based on a window of acceptable sequence numbers {{RFC4303}}.

### Protocol Features

- Anti-replay protection between datagrams.
- Basic reliability for handshake messages.
- See also the features from TLS.

### Protocol Dependencies

- Since DTLS runs over an unreliable, unordered datagram transport, it does not require any reliability features.
- DTLS contains its own length, so although it runs over a datagram transport, it does not rely on the transport protocol supporting framing.
- UDP for port numbers used for demultiplexing.
- Path MTU discovery.

## QUIC with TLS

QUIC (Quick UDP Internet Connections) is a new transport protocol that runs over UDP, and was
originally designed with a tight integration with its security protocol and application protocol
mappings. The QUIC transport layer itself provides support for data confidentiality and integrity.
This requires keys to be derived with a separate handshake protocol. A mapping for QUIC over
TLS 1.3 {{I-D.ietf-quic-tls}} has been specified to provide this handshake.

### Protocol Description

Since QUIC integrates TLS with its transport, it relies on specific integration points
between its security and transport sides. Specifically, these points are:

- Starting the handshake to generate keys and provide authentication (and providing the transport for the handshake).
- Client address validation.
- Key ready events from TLS to notify the QUIC transport.
- Exporting secrets from TLS to the QUIC transport.

The QUIC transport layer support multiple streams over a single connection. The first
stream is reserved specifically for a TLS connection. The TLS handshake, along with
further records, are sent over this stream. This TLS connection follows the TLS standards
and inherits the security properties of TLS. The handshake generates keys, which are
then exported to the rest of the QUIC connection, and are used to protect the rest of the streams.

The initial QUIC messages are sent without encryption in order to start the TLS handshake.
Once the handshake has generated keys, the subsequent messages are encrypted. The TLS 1.3
handshake for QUIC is used in either a single-RTT mode or a fast-open zero-RTT mode. When
zero-RTT handshakes are possible, the encryption first transitions to use the zero-RTT keys
before using single-RTT handshake keys after the next TLS flight.

### Protocol Features

- Handshake properties of TLS.
- Multiple encrypted streams over a single connection without head-of-line blocking.
- Packet payload encryption and complete packet authentication (with the exception of the Public Reset packet, which is not authenticated).

### Protocol Dependencies

- QUIC transport relies on UDP.
- QUIC transport relies on TLS 1.3 for authentication and initial key derivation.
- TLS within QUIC relies on a reliable stream abstraction for its handshake.

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

- 0-RTT forward secrecy for new connections.
- DoS prevention by client-side puzzles.
- Tunnel-based mobility.
- (Transport Feature) Connection multiplexing between hosts across shared tunnels.
- (Transport Feature) Congestion control state is shared across connections between the same host pairs.

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
either end to share secret keying material. And it allows ephemeral public keys to be associated with connections (or sessions).

The client and server do not perform a standard key exchange. Instead, in the initial exchange of packets, the each party provides its
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

Unlike some other protocols, CurveCP data packets only leave the ephemeral public key, i.e., the connection ID, and the per-message nonce
in the clear. Everything else is encrypted.

### Protocol Features

- Forward-secure data encryption and authentication.
- Per-packet public-key encryption.
- 1-RTT session bootstrapping.
- Connection mobility based on a client-chosen ephemeral identifier.
- Connection establishment message padding to prevent traffic amplification.
- Sender-chosen explicit nonces, e.g., based on a sequence number.

### Protocol Dependencies

- An unreliable transport protocol such as UDP.

## tcpcrypt

tcpcrypt is a lightweight extension to the TCP protocol to enable opportunistic encryption.

### Protocol Description

tcpcrypt extends TCP to enable opportunistic encryption between the two ends of a TCP connection {{I-D.ietf-tcpinc-tcpcrypt}}.
It is a type of TCP Encryption Protocol (TEP). The use of a TEP is negotiated using TCP headers
during the initial TCP handshake. Negotiating a TEP also involves agreeing upon a key exchange algorithm.
If and when a TEP is negotiated, the tcpcrypt key exchange occurs within the data segments of
the first packets exchanged after the handshake completes. The initiator of a connection
sends a list of support AEAD algorithms, a random nonce, and an ephemeral public key share. The
responder chooses an AEAD algorithm and replies with its own nonce and ephemeral key share.
The traffic encryption keys are derived from the key exchange.

Each tcpcrypt session is associated with a unique session ID; the value of which is derived from the current
shared secret used for the session. This can be cached and used to later resume a session.
Willingness to resume a session is signaled within the TCP-ENO negotiation option
during the TCP handshake {{I-D.ietf-tcpinc-tcpeno}}. Session identifiers are rotated each time they are resumed. Sessions may
also be re-keyed if the natural AEAD limit is reached.

tcpcrypt only encrypts the data portion of a TCP packet. It does not encrypt any header information,
such as the TCP sequence number.

### Protocol Features

- Forward-secure TCP packet encryption.
- Session caching and address-agnostic resumption.
- Session re-keying.

### Protocol Dependencies

- TCP (with option support).

## IKEv2 with ESP

IKEv2 {{RFC7296}} and ESP {{RFC4303}} together form the modern IPsec protocol suite that encrypts and authenticates IP packets, either as for creating tunnels (tunnel-mode) or for direct transport connections (transport-mode). This suite of protocols separates out the key generation protocol (IKEv2) from the transport encryption protocol (ESP). Each protocol can be used independently, but this document considers them together, since that is the most common pattern.

### Protocol descriptions

#### IKEv2

IKEv2 is a control protocol that runs on UDP port 500. Its primary goal is to generate keys for Security Associations (SAs). It first uses a Diffie-Hellman key exchange to generate keys for the "IKE SA", which is a set of keys used to encrypt further IKEv2 messages. It then goes through a phase of authentication in which both peers present blobs signed by a shared secret or private key, after which another set of keys is derived, referred to as the "Child SA". These Child SA keys are used by ESP.

IKEv2 negotiates which protocols are acceptable to each peer for both the IKE and Child SAs using "Proposals". Each proposal may contain an encryption algorithm, an authentication algorithm, a Diffie-Hellman group, and (for IKE SAs only) a pseudorandom function algorithm. Each peer may support multiple proposals, and the most preferred mutually supported proposal is chosen during the handshake.

The authentication phase of IKEv2 may use Shared Secrets, Certificates, Digital Signatures, or an EAP (Extensible Authentication Protocol) method. At a minimum, IKEv2 takes two round trips to set up both an IKE SA and a Child SA. If EAP is used, this exchange may be expanded.

Any SA used by IKEv2 can be rekeyed upon expiration, which is usually based either on time or number of bytes encrypted.

There is an extension to IKEv2 that allows session resumption {{RFC5723}}.

MOBIKE is a Mobility and Multihoming extension to IKEv2 that allows a set of Security Associations to migrate over different addresses and interfaces {{RFC4555}}.

When UDP is not available or well-supported on a network, IKEv2 may be encapsulated in TCP {{I-D.ietf-ipsecme-tcp-encaps}}.

#### ESP

ESP is a protocol that encrypts and authenticates IP and IPv6 packets. The keys used for both encryption and authentication can be derived from an IKEv2 exchange. ESP Security Associations come as pairs, one for each direction between two peers. Each SA is identified by a Security Parameter Index (SPI), which is marked on each encrypted ESP packet.

ESP packets include the SPI, a sequence number, an optional Initialization Vector (IV), payload data, padding, a length and next header field, and an Integrity Check Value.

From {{RFC4303}}, "ESP is used to provide confidentiality, data origin authentication, connectionless integrity, an anti-replay service (a form of partial sequence integrity), and limited traffic flow confidentiality."

Since ESP operates on IP packets, it is not directly tied to the transport protocols it encrypts. This means it requires little or no change from transports in order to provide security.

ESP packets are sent directly over IP, except when a NAT is present, in which case they are sent on UDP port 4500, or via TCP encapsulation {{I-D.ietf-ipsecme-tcp-encaps}}.

### Protocol features

#### IKEv2

- Encryption and authentication of handshake packets.
- Cryptographic algorithm negotiation.
- Session resumption.
- Mobility across addresses and interfaces.
- Peer authentication extensibility based on Shared Secret, Certificates, Digital Signatures, or EAP methods.

#### ESP

- Data confidentiality and authentication.
- Connectionless integrity.
- Anti-replay protection.
- Limited flow confidentiality.

### Protocol dependencies

#### IKEv2

- Availability of UDP to negotiate, or implementation support for TCP-encapsulation.
- Some EAP authentication types require accessing a hardware device, such as a SIM card; or interacting with a user, such as password prompting.

#### ESP

- Since ESP is below transport protocols, it does not have any dependencies on the transports themselves, other than on UDP or TCP for NAT traversal.

## SRTP

XXX: https://tools.ietf.org/html/rfc3711
XXX: https://tools.ietf.org/html/rfc5763

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## ZRTP

XXX: http://zfoneproject.com/faq.html#keycontinuity

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## SS-TLS

XXX

https://www.esat.kuleuven.be/cosic/publications/article-2806.pdf

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## WireGuard

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## NoiseSocket

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## CurveCP

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## OTR

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## Signal

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

## NTor

XXX

### Protocol descriptions

XXX

### Protocol features

XXX

### Protocol dependencies

XXX

# Common Transport Security Features

There exists a common set of features shared across the transport protocols surveyed in this document.
The mandatory features should be provided by any transport security protocol, while the optional features
are extensions that a subset of the protocols provide. For clarity, we also distinguish between handshake
and record features.

## Mandatory Features

### Handshake

- Forward-secure segment encryption and authentication: Transit data must be protected with an
authenticated encryption algorithm.

- Private key interface or injection: Authentication based on public key signatures is commonplace for
many transport security protocols.

- Endpoint authentication: The endpoint (receiver) of a new connection must be authenticated before any
data is sent to said party.

- Source validation: Source validation must be provided to mitigate server-targeted DoS attacks. This can
be done with puzzles or cookies.

### Record

- Pre-shared key support: A record protocol must be able to use a pre-shared key established
out-of-band to encrypt individual messages, packets, or datagrams.

## Optional Features

### Handshake

- Mutual authentication: Transport security protocols should allow both endpoints to authenticate one another if needed.

- Application-layer feature negotiation: The type of application using a transport security protocol often requires
features configured at the connection establishment layer, e.g., ALPN {{RFC7301}}. Moreover, application-layer features may often be used to
offload the session to another server which can better handle the request. (The TLS SNI is one example of such a feature.)
As such, transport security protocols should provide a generic mechanism to allow for such application-specific features
and options to be configured or otherwise negotiated.

- Configuration extensions: The protocol negotiation should be extensible with addition of new configuration options.

- Session caching and management: Sessions should be cacheable to enable reuse and amortize the cost of performing
session establishment handshakes.

### Record

- Connection mobility: Sessions should not be bound to a network connection (or 5 tuple). This allows cryptographic
key material and other state information to be reused in the event of a connection change. Examples of this include
a NAT rebinding that occurs without a client's knowledge.

# Transport Security Protocol Interfaces

This section describes the interface surface exposed by the security protocols described
above, with each interface. Note that not all protocols support each interface.

## Configuration Interfaces

Configuration interfaces are used to configure the security protocols before a
handshake begins or the keys are negotiated.

- Identity and Private Keys  
The application can provide its identities (certificates) and private keys, or
mechanisms to access these, to the security protocol to use during handshakes.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2

- Supported Algorithms (Key Exchange, Signatures and Ciphersuites)  
The application can choose the algorithms that are supported for key exchange,
signatures, and ciphersuites.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2

- Session Cache  
The application provides the ability to save and retrieve session state (tickets,
keying material, server parameters) that may be used to resume the security session.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT

- Authentication Delegate  
The application provides access to a separate module that will provide authentication,
using EAP for example.  
Protocols: IKEv2

## Handshake Interfaces

Handshake interfaces are the points of interaction between a handshake protocol and
the application, record protocol, and transport once the handshake is active.

- Send Handshake Messages  
The handshake protocol needs to be able to send messages over a transport to the remote peer to establish trust and negotiate keys.  
Protocols: All (TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2)

- Receive Handshake Messages  
The handshake protocol needs to be able to receive messages from the remote peer
over a transport to establish trust and negotiate keys.  
Protocols: All (TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2)

- Identity Validation  
During a handshake, the security protocol will conduct identity validation of the peer.
This can call into the application to offload validation.  
Protocols: All (TLS, DTLS, QUIC + TLS, MinimalT, CurveCP, IKEv2)

- Source Address Validation  
The handshake protocol may delegate validation of the remote peer that has sent
data to the transport protocol or application. This involves sending a cookie
exchange to avoid DoS attacks.  
Protocols: QUIC + TLS

- Key Update  
The handshake protocol may be instructed to update its keying material, either
by the application directly or by the record protocol sending a key expiration event.  
Protocols: TLS, DTLS, QUIC + TLS, MinimalT, tcpcrypt, IKEv2

- Pre-Shared Key Export  
The handshake protocol will generate one or more keys to be used for record encryption/decryption and authentication. These may be explicitly exportable to the application, traditionally limited to direct  export to the record protocol, or inherently non-exportable because the keys must be used directly in conjunction with the record protocol.  
    - Explict export: TLS (for QUIC), tcpcrypt, IKEv2
    - Direct export: TLS, DTLS, MinimalT
    - Non-exportable: CurveCP

## Record Interfaces

Record interfaces are the points of interaction between a record protocol and the application, handshake protocol, and transport once in use.

- Pre-Shared Key Import  
Either the handshake protocol or the application directly can supply pre-shared keys for the record protocol use for encryption/decryption and authentication. If the application can supply keys directly, this is considered explicit import; if the handshake protocol traditionally provides the keys directly, it is considered direct import; if the keys can only be shared by the handshake, they are considered non-importable.
    - Explict import: QUIC, ESP
    - Direct import: TLS, DTLS, MinimalT, tcpcrypt
    - Non-importable: CurveCP

- Encrypt application data  
The application can send data to the record protocol to encrypt it into a format that can be sent on the underlying transport. The encryption step may require that the application data is treated as a stream or as datagrams, and that the transport to send the encrypted records present a stream or datagram interface.  
    - Stream-to-Stream Protocols: TLS, tcpcrypt
    - Datagram-to-Datagram Protocols: DTLS, ESP
    - Stream-to-Datagram Protocols: QUIC ((Editor's Note: This depends on the interface QUIC exposes to applications.))

- Decrypt application data  
The application can receive data from its transport to be decrypted using record protocol. The decryption step may require that the incoming transport data is presented as a stream or as datagrams, and that the resulting application data is a stream or datagrams.  
    - Stream-to-Stream Protocols: TLS, tcpcrypt
    - Datagram-to-Datagram Protocols: DTLS, ESP
    - Datagram-to-Stream Protocols: QUIC ((Editor's Note: This depends on the interface QUIC exposes to applications.))

- Key Expiration  
The record protocol can signal that its keys are expiring due to reaching a time-based deadline, or a use-based deadline (number of bytes that have been encrypted with the key). This interaction is often limited to signaling between the record layer and the handshake layer.  
Protocols: ESP ((Editor's note: One may consider TLS/DTLS to also have this interface))

- Transport mobility  
The record protocol can be signaled that it is being migrated to another transport or interface due to connection mobility, which may reset address and state validation.  
Protocols: QUIC, MinimalT, CurveCP, ESP

# IANA Considerations

This document has on request to IANA.

# Security Considerations

N/A

# Acknowledgments

The authors would like to thank Mirja Kühlewind, Brian Trammell, Yannick Sierra,
Frederic Jacobs, and Bob Bradley for their input and feedback on earlier versions
of this draft.
