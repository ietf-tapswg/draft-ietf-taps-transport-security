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

TLS is..
[CHRIS]

## DTLS

[TOMMY]

## QUIC with TLS

[TOMMY]

## MinimalT

[CHRIS]

## CurveCP

[CHRIS]

## tcpcrypt

[CHRIS]

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
- Session resumption
- Mobility across addresses and interfaces
- Authentication based on Shared Secret, Certificates, Digital Signatures, or EAP methods

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

## TLS

TLS has...
[CHRIS]

## DTLS

[TOMMY]

## QUIC with TLS

[TOMMY]

## MinimalT

[CHRIS]

## CurveCP

[CHRIS]

## tcpcrypt

[CHRIS]

## IKEv2 with ESP

[TOMMY]

# Minimum Common Transport Security Set

## Mandatory Features
- authentication (identities, private keys, etc)
- encryption
- resumption

[CHRIS]

## Optional Features

- address validation

# IANA Considerations

This document has on request to IANA.

# Security Considerations

XXX

# Acknowledgments

XXX
