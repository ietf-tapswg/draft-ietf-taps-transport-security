---
title: A Survey of Transport Security Protocols
abbrev: transport security survey
docname: draft-pauly-transport-security-00
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
    ins: XXX
    name: XXX
    org: XXX
    email: XXX
    street: XXX
    city: XXX
    country: XXX

normative:
    RFC5246:

--- abstract

XXX

--- middle

# Introduction

- TLS
- DTLS
- QUIC+TLS
- QUIC+foo
- MinimalT
- CurveCP
- tcpcrypt
- IPsec (IKE+ESP/AH) [?]

[TOMMY]

# Terminology

The following terms are used throughout this document to describe the roles and interactions of transport security protocols:

- Transport Feature: a specific end-to-end feature that the transport layer provides to an application.  Examples include confidentiality, reliable delivery, ordered delivery, message-versus-stream orientation, etc.

- Transport Service: a set of Transport Features, without an association to any given framing protocol, which provides a 

- Transport Protocol: an implementation that provides one or more different transport services using a specific framing and header format on the wire.complete service to an application.

- Application: an entity that uses the transport layer for end-to-end delivery of data across the network (this may also be an upper layer protocol or tunnel encapsulation).

- Security Feature: a specific feature that a network security layer provides to applications. Examples include authentication, encryption, key generation, session resumption, and privacy. A feature may be considered to be Mandatory or Optional to a TAPS implementation.

- Security Protocol: a defined network protocol that implements one or more security features. Security protocols may be used alongside transport protocols, and in combination with one another when appropriate.

# Current Transport Security Protocols

This section contains descriptions of security protocols that currently used to protect data being sent over a network.

For each protocol, we describe the features it provides and its dependencies on other protocols.

## TLS

TLS (Transport Layer Security) {{RFC5246}} is a common protocol used to establish a secure session between two endpoints. Communication
over this session "prevents eavesdropping, tampering, and message forgery." TLS consists
of a handshake and record protocol. The handshake protocol is used to negotiate a shared secret and corresponding cryptographic algorithms. 
The record protocol is used to transfer and, after handshake completion, encryption and authentication of all data. 

### Protocol Description

TLS is the composition of a handshake and record protocol. 
The record protocol is designed to marshall an arbitrary, in-order stream of bytes from one endpoint to the other. 
It handles segmenting, compressing (when enabled), and encrypting data into discrete records. When configured
to use an AEAD algorithm, it also handles nonce generation and encoding for each record. The record protocol is 
hidden from the client behind a byte stream-oriented API. 

The handshake protocol serves to negotiate a version and cryptographic parameters. At a minimum, this includes 
the key exchange algorithm and ciphersuite to use in the record protocol. The handshake supports mutual authentication
for both the session initiator (client) and receiver (server). Commonly, only the server is authenticated. X.509
certificates are used in this authentication process. Each party may require explicit certificate status requests
from the peer to verify the legitimacy of their certificate.

The handshake protocol is also extensible. It allows for a variety of extensions to be included by either the client
or server. These extensions are used to specify client preferences, e.g., the application-layer protocol to be driven
with the TLS connection, or signals to the server to aid operation, e.g., the server name. Various extensions also exist
to tune the parameters of the record protocol, e.g., the maximum fragment length. 

Alerts are used to convey errors and other atypical events to the endpoints. There are two classes of alerts: closure
and error alerts. A closure alert is used to signal to the other peer that the sender wishes to terminate the connection.
The sender typically follows a close alert with a TCP FIN segment to close the connection. Error alerts are used to
indicate problems with the handshake or individual records. Most errors are fatal and are followed by connection
termination. However, warning alerts may be handled at the discretion of each respective implementation. 

Once a session is disconnected all keying material must be torn down, unless resumption information was previously
negotiated. TLS supports stateful and stateless resumption. (Here, the state refers to the information requirements
for the server. It is assumed that the client must always store some state information in order to resume a session.)

### Protocol Features

- Key exchange and ciphersuite algorithm negotiation.
- Stateful and stateless session resumption.
- Anonymous key exchange.
- Certificate- and raw public-key-based authentication.
- Mutual client and server authentication.
- Byte stream confidentiality and integrity.
- Extensibility via well-defined extensions.
- 0-RTT data support (in TLS 1.3 only).
- Application-layer protocol negotiation.
- Transparent data segmentation.

### Protocol Dependencies

- TCP for in-order, reliable transport.
- A PKI trust store for certificate validation.

## DTLS

[TOMMY]

## QUIC with TLS

[TOMMY]

## MinimalT [CHRIS]

MinimalT is a UDP-based transport security protocol desiged to offer confidentiality, mutual authentication, DoS prevention, and connection
mobility. One major goal of the protocol is to leverage existing protocols to obtain server-side configuration information used to 
more quickly bootstrap a connection. MinimalT uses a variant of TCP's congestion control algorithm.

### Protocol Description

MinimalT is a secure transport protocol built on top of a widespread directory service. Clients and servers interact with local directory
services to (a) resolve server information and (b) public ephemeral state information, respectively. Clients connect to a local
resolver once at boot time. Through this resolver they recover the IP address(es) and public key(s) of each server to which
they want to connect. 

Connections are instances of user-authenticated, mobile sessions between two endpoints. Connections run within tunnels between hosts. A tunnel
is a server-authenticated containers that multiplex multiple connections between the same hosts. All connections in a tunnel share the
same transport state machine and encryption. Each tunnel has a dedicated control connection used to configure and manage the tunnel over time. 
Moreover, since tunnels are independent of the network address information, they may be reused as both ends of the tunnel move about the network.

Before a client connects to a remote service, it must first esbtalish a tunnel to the host providing or offering the service. Tunnels are established
in 1-RTT using an ephemeral key obtained from the directory service. Tunnel initiators provide their own ephemeral key and, optionally, a 
DoS puzzle solution such that the recipient (server) can verify the authenticity of the request and derive a shared secret. Within a tunnel,
new connections to services may be established. 

### Protocol Features

- Connection multiplexing between hosts across shared tunnels
- Congestion control state is shared across connections between the same host pairs
- 0-RTT forward secrecy for new connections.
- DoS prevention by client-side puzzles.
- Tunnel-based mobility.

### Protocol Dependencies

- A DNS-like resolution service to obtain location information (an IP address) and ephemeral keys. 
- A PKI trust store for certificate validation.

## CurveCP [CHRIS]

XXX

### Protocol Description

TODO

### Protocol Features

- Data confidentiality and integrity
- 

### Protocol Dependencies

TODO

## tcpcrypt [CHRIS]

tcpcrypt is an extension to the TCP protocol to enable opportunistic encryption. 

### Protocol Description

### Protocol Features

- Forward-secure TCP packet encryption.
- Hooks for external authentcation.

### Protocol Dependencies

- TCP.

## IKEv2 with ESP

IKEv2 [RFC 7296] and ESP [RFC 4303] together form the modern IPsec protocol suite that encrypts and authenticates IP packets, either as for creating tunnels (tunnel-mode) or for direct transport connections (transport-mode). This suite of protocols separates out the key generation protocol (IKEv2) from the transport encryption protocol (ESP). Each protocol can be used independently, but this document considers them together, since that is the most common pattern.

### Protocol descriptions

#### IKEv2

IKEv2 is a control protocol that runs on UDP port 500. Its primary goal is to generate keys for Security Associations (SAs). It first uses a Diffie-Hellman key exchange to generate keys for the "IKE SA", which is a set of keys used to encrypt further IKEv2 messages. It then goes through a phase of authentication in which both peers present blobs signed by a shared secret or private key, after which another set of keys is derived, referred to as the "Child SA". These Child SA keys are used by ESP.

IKEv2 negotiates which protocols are acceptable to each peer for both the IKE and Child SAs using "Proposals". Each proposal may contain an encryption algorithm, an authentication algorithm, a Diffie-Hellman group, and (for IKE SAs only) a Psuedorandom-Function algorithm. Each peer may support multiple proposals, and the most preferred mutually supported proposal is chosen during the handshake.

The authentication phase of IKEv2 may use Shared Secrets, Certificates, Digital Signatures, or an EAP (Extensible Authentication Protocol) method. At a minimum, IKEv2 takes two round trips to set up both an IKE SA and a Child SA. If EAP is used, this exchange may be expanded.

Any SA used by IKEv2 can be rekeyed upon expiration, which is usually based either on time or number of bytes encrypted. 

There is an extension to IKEv2 that allows session resumption [RFC 5723].

MOBIKE is a Mobility and Multihoming extension to IKEv2 that allows a set of Security Associations to migrate over different addresses and interfaces [RFC 4555].

When UDP is not available or well-supported on a network, IKEv2 may be encapsulated in TCP [tcp-encaps].

#### ESP

ESP is a protocol that encrypts and authenticates IP and IPv6 packets. The keys used for both encryption and authentication can be derived from an IKEv2 exchange. ESP Security Associations come as pairs, one for each direction between two peers. Each SA is identified by a Security Parameter Index (SPI), which is marked on each encrypted ESP packet.

ESP packets include the SPI, a sequence number, an optional Initialization Vector (IV), payload data, padding, a length and next header field, and an Integrity Check Value.

From [RFC 4303], "ESP is used to provide confidentiality, data origin authentication, connectionless integrity, an anti-replay service (a form of partial sequence integrity), and limited traffic flow confidentiality."

Since ESP operates on IP packets, it is not directly tied to the transport protocols it encrypts. This means it requires little or no change from transports in order to provide security.

ESP packets are sent directly over IP, except when a NAT is present, in which case they are sent on UDP port 4500, or via TCP encapsulation.

### Protocol features

#### IKEv2

- Encryption and authentication of control handshake
- Sets of crypto algorithms that can be negotiated
- Long-lived sessions with resumption
- Mobility across addresses and interfaces
- Authentication extensibility based on Shared Secret, Certificates, Digital Signatures, or EAP methods

#### ESP

- Confidentiality
- Authentication
- Connectionless integrity
- Anti-replay protection
- Limited flow confidentiality

### Protocol dependencies

#### IKEv2

- Availability of UDP to negotiate, or implementation support for TCP-encapsulation.
- Some EAP authentication types require accessing a hardware device, such as a SIM card; or interacting with a user, such as password prompting.

#### ESP

- Since ESP is below transport protocols, it does not have any dependencies on the transports themselves, other than on UDP or TCP for NAT traversal.

# Security Protocol Interfaces

This section covers the set of knobs exposed by each security protocol. These fall into categories of Mandatory, Optimizing, and Automatable options.

## TLS [CHRIS]

- Identity information (certificates) and private keys (or interfaces to private keys)
- Ciphersuite configuration
- Signature algorithm selection
- Interface to session ticket encryption keys
- Session cache management
- XXX

## DTLS

[TOMMY]

## QUIC with TLS

[TOMMY]

## MinimalT [CHRIS]

- XXX

## CurveCP [CHRIS]

- XXX

## tcpcrypt [CHRIS]

- XXX

## IKEv2 with ESP

[TOMMY]

# Minimum Common Transport Security Set [CHRIS]

## Mandatory Features
- authentication (identities, private keys, etc)
- encryption
- resumption

## Optional Features

- source validation [puzzles, cookies]

# IANA Considerations

This document has on request to IANA.

# Security Considerations

XXX

# Acknowledgments

XXX
