# Cloud Shared Responsibility Matrix (SRM)

> **AI Disclaimer:** This template was generated with the assistance of AI. It must be customized based on your specific CSP (AWS, Azure, GCP) and service model (IaaS, PaaS, SaaS).
> **Audit Evidence Reference:** CCM-STA-03 | RMiT 10.50

## 1. Overview
This matrix defines the security responsibilities between [Organization Name] and [CSP Name].

| Control Area | CSP Responsibility | Customer Responsibility | Shared? |
| :--- | :--- | :--- | :--- |
| **Physical Data Centre** | Full Control (Security, Cooling, Power) | None | No |
| **Hypervisor Security** | Patching & Configuration | None | No |
| **Network Security** | Infrastructure Isolation | Security Groups / WAF Rules | Yes |
| **Guest OS Patching** | None (IaaS) | Full Control | No |
| **Application Security** | None | Full Development Lifecycle | No |
| **Identity & IAM** | Service Availability | User Provisioning / MFA | Yes |
| **Data Encryption** | KMS Service | Key Management / Policy | Yes |

## 2. Shared Responsibility Sign-off
**Internal Reviewer:**
**Date:**
