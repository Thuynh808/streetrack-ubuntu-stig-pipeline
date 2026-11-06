# Streetrack Ubuntu 24.04 STIG Compliance Pipeline

## Project Overview

An assessment and hardening workflow for **Ubuntu 24.04 LTS on Azure**, built with Ansible, Python, and Tenable Vulnerability Management. The project combines credentialed STIG assessments, automated remediation, operational checks, and residual findings review against the **DISA Canonical Ubuntu 24.04 LTS STIG v1r5** benchmark.

Verification showed an improvement from **30.6% to 91.2% measured compliance**, with **111 fewer failed controls**.

## Results

| Assessment | Passed | Failed | Warning / Manual Review | Measured Compliance |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 56 | 127 | 12 | 30.6% |
| Verification | 166 | 16 | 13 | 91.2% |

**Failed controls decreased by 87.4%.** Measured compliance is calculated as passed ÷ (passed + failed); warning/manual review checks are excluded and require separate review.

## Components

| Component | Role |
| --- | --- |
| Ubuntu 24.04 LTS / Azure | Target server and hosting environment |
| Tenable Vulnerability Management | Credentialed baseline and verification assessments |
| Ansible / UBUNTU24-STIG | Upstream STIG hardening |
| Custom `streetrack_stig` role | Additional remediation organized by CAT I, II, and III controls |
| Python / REST API | Scan creation, launch, status polling, and HTML report export |
| Bash / Ansible | Connectivity, privilege escalation, service, network, and firewall checks |

## Workflow

**Assess → Review → Remediate → Validate → Verify → Review Residual Findings**

1. Capture a credentialed baseline assessment and review failed controls.
2. Apply the upstream hardening role and custom remediations for PAM, password hashing, session timeouts, UFW, logging, audit settings, and file permissions.
3. Run functionality checks and repeat remediation to assess repeat-run behavior.
4. Perform a verification assessment, compare results, and document remaining findings.

## Implementation & Evidence

- **[Ansible playbook](ansible/site.yaml)** — coordinates updates, upstream hardening, an explicit SSH confirmation exception, and custom remediation.
- **[Custom remediation role](ansible/roles/streetrack_stig)** — control-specific tasks, configurable defaults, and service handlers.
- **[Scan automation](scripts/nessus_scan.py)** — runs baseline or verification scans and preserves HTML reports.
- **[Functionality validation](scripts/functionality_test.sh)** — records operational smoke checks after hardening.
- **[Assessment reports](evidence)** — baseline and verification HTML/PDF reports, Ansible execution logs, and functionality logs.
- **[Residual Findings Summary](evidence/Streetrack_STIG_Residual_Findings.pdf)** — categorizes all 16 remaining failed controls and recommended treatment.
- **[Standard Operating Procedure](Streetrack_STIG_Pipeline_SOP.pdf)** — defines prerequisites, responsibilities, acceptance criteria, and reassessment procedures.

## Scope & Limitations

This repository preserves a single-server lab implementation and its assessment evidence. Remaining failures include enterprise identity/PKI, centralized audit storage, FIPS, boot/time configuration, and two local configuration weaknesses.

Both Ansible runs completed with **zero failed or unreachable hosts**. The second run reported **19 changes**, so full idempotency remains future work. Reuse also requires restoring the upstream role dependency and adapting inventory, credentials, and scanner configuration to the target environment.
