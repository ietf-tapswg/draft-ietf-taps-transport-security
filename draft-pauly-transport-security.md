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

[TOMMY]

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

[TOMMY]

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
