
# Autonomous Public Key Infrastructure (Auto PKI)

## Introduction

Auto PKI is a framework for managing trust relationships between entities in a distributed system. It is based on the concept of public key infrastructure (PKI) and is designed to be fully automated. Auto PKI is fully backwards compatible with the X.509 standard for PKI certificates. Auto extends the standard PKI system with the notion of a registry, which is a distributed database of all registered certificates in the system. The registry is permissionless, in that it allows anyone to register as an issuer of certificates, or a root Certificate Authority (CA), in traditional terminology. The issuer may then certify other entities who may register as subjects, including intermediate issuers and end entities. 

## Key Terms

* Issuer
* Subject
* Certificate
* Certificate Authority (CA)
* Certificate Signing Request (CSR)
* Public Key
* Private Key
* Certificate Revocation List (CRL)
* Registry (or Directory)