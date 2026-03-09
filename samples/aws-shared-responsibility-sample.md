# Worked Example: Cloud Shared Responsibility Matrix (AWS IaaS)

> **AI Disclaimer:** This is a **SAMPLE** completed matrix for educational purposes.
> **Audit Evidence Reference:** CCM-STA-03 | RMiT 10.50

## 1. Project Context
*   **Organization:** Fin-Tech Malaysia
*   **Provider:** Amazon Web Services (AWS)
*   **Region:** ap-southeast-1 (Singapore)
*   **Service Model:** Infrastructure as a Service (IaaS) - EC2, EBS, S3

## 2. Responsibility Allocation

| Control Area | AWS Responsibility | Fin-Tech Responsibility | Shared? |
| :--- | :--- | :--- | :--- |
| **Data Residency** | Physical Infrastructure | Region selection (ap-southeast-1) | Yes |
| **OS Patching** | None | Patching of EC2 Windows Instances | No |
| **S3 Encryption** | KMS Availability | KMS Policy & Bucket Configuration | Yes |
| **Security Groups** | Service API | Port/IP Rule Definitions | Yes |
| **MFA** | Console Support | IAM User Enrollment | Yes |

## 3. Compliance Confirmation
The Shared Responsibility Model has been reviewed against the **BNM RMiT Nov 2025** requirements for cloud adoption.

---
**Reviewer:** Sarah Wong (Cloud Architect)
**Date:** 2026-03-08
