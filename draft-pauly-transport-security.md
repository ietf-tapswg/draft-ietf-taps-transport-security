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

# Current Transport Security Protocols

This section contains descriptions of security protocols that currently used to protect data being sent over a network.

For each protocol, we describe the features it provides and its dependencies on other protocols.

## TLS

TLS is..

## DTLS

## QUIC with TLS

## MinimalT

## CurveCP

## tcpcrypt

## IKEv2 with ESP

# Security Protocol Interfaces

This section covers the set of knobs exposed by each security protocol. These fall into categories of Mandatory, Optimizing, and Automatable options.

## TLS

TLS has...

## DTLS

## QUIC with TLS

## MinimalT

## CurveCP

## tcpcrypt

## IKEv2 with ESP

# Minimum Common Transport Security Set

## Mandatory Features
- authentication (identities, private keys, etc)
- encryption
- resumption

## Optional Features

- address validation

# IANA Considerations

This document has on request to IANA.

# Security Considerations

XXX

# Acknowledgments

XXX
