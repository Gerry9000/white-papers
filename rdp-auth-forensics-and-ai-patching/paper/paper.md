# RDP Authentication Forensics and AI-Assisted Patching of GNOME Remote Desktop 49.0

**Author**: Gerry Burde
**Date**: February 2026
**Version**: 1.0

---

## Abstract

GNOME Remote Desktop 49.0, the default RDP server in Ubuntu 25.10, fails to complete sessions with Windows mstsc.exe on headless virtual machines -- a black screen after login, reported across multiple distributions since 2023 without resolution. Using agentic AI tooling, a cybersecurity professional with no prior C development or RDP protocol experience investigated the root cause and developed a working patch. The AI-assisted analysis identified five bugs and produced a fix that resolved the connection failures for both mstsc.exe and FreeRDP clients. But continued research -- verifying the AI's claims against source code, commit history, and protocol implementations -- revealed that only one bug actually required a fix, in a different package than originally patched. The progression from a working five-bug patch to a verified single-line fix demonstrates both what AI-assisted security research makes possible and why adversarial verification of AI output is essential. The fix affects GNOME 46-49 across multiple distributions and has been submitted upstream ([MR !474](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474)).

---

## 1. Technical Background

### 1.1 Motivation

GNOME Remote Desktop has been the default remote desktop server in Ubuntu since 22.04, and GNOME is the default desktop environment across most major Linux distributions. As organizations adopt Ubuntu for development workstations, cloud-hosted VMs, and internal infrastructure, RDP access to GNOME sessions becomes a basic operational requirement -- developers and administrators on mixed-OS networks need to connect from Windows machines using the built-in Remote Desktop Connection client (mstsc.exe).

This investigation began when we attempted to enable RDP access to headless Ubuntu 25.10 VMs for a development team evaluating Ubuntu Desktop as a remote development platform ahead of the 26.04 LTS release. The connection failures were not a misconfiguration -- they were bugs in GRD's session handover lifecycle that affected every RDP client on every headless GNOME system running the current release.

The urgency of these bugs extends beyond the current release. GNOME 50, shipping in Ubuntu 26.04 LTS (April 2026), removes X11 backend support entirely from Mutter and GNOME Shell -- the desktop runs exclusively on Wayland. The widely-used xrdp package depends on X11/Xorg for its virtual display backend and has no Wayland support, with the xrdp project acknowledging that migration from X11 to Wayland "brings a lot of challenges" and no timeline for completion. This means GRD becomes the **only viable RDP server** for the default Ubuntu Desktop environment starting with the next LTS release -- a 5-year support window covering enterprise deployments, cloud-hosted VMs, and VPS offerings.

### 1.2 RDP Authentication Protocols

RDP supports multiple security mechanisms: **NLA** (pre-session authentication via CredSSP/NTLM), **TLS** (encrypted channel, post-session authentication), and **RDSTLS** (carries pre-authenticated credentials after server redirection). Protocol negotiation is one-shot -- the server selects a single protocol from the client's proposed set, with priority RDSTLS > NLA > TLS. There is no fallback; if the selected protocol fails, the connection drops.

These protocols are mentioned because the AI's initial analysis incorrectly identified them as the root cause. They turned out to be irrelevant -- the actual bug is a service lifecycle issue, not a protocol negotiation issue. But the protocol terminology made the incorrect analysis sound plausible.

### 1.3 GRD Runtime Modes

GRD operates in four runtime modes, each activated by a command-line flag:

| Mode | Flag | Purpose |
|------|------|---------|
| SCREEN_SHARE | (default) | Desktop sharing for an active user session |
| HEADLESS | `--headless` | Headless VNC/RDP server |
| SYSTEM | `--system` | Pre-login RDP server on port 3389, managed by systemd |
| HANDOVER | `--handover` | Post-redirect session daemon in the user's login session |

The **system-to-handover flow** is critical for headless VMs:

1. The **system daemon** listens on port 3389 and presents the GDM login screen
2. After the user authenticates at GDM, the system daemon issues an **RDP server redirect** to the user session's handover daemon
3. The **handover daemon** starts in the user's session and calls `RequestHandover` via D-Bus to claim the redirected connection
4. The client disconnects from the system daemon and reconnects to the handover daemon

The handover daemon enables RDSTLS on the server side (commit [`ff5a85e`](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/ff5a85e), November 2023). The commit message explicitly notes: "Only with this security method enabled, the mstsc client can do a redirection and successfully authenticate." The stock code also creates a SAM database for NLA and keeps NLA enabled alongside RDSTLS in handover mode.

### 1.4 The Affected Configuration

The failure affects all RDP clients connecting to headless virtual machines (tested on Hyper-V Gen2) running Ubuntu 25.10 with GRD 49.0 in system mode. Testing confirmed that both mstsc.exe (Windows) and xfreerdp3 (FreeRDP Linux client) fail on unpatched GRD, and both succeed on patched GRD. The root cause is in GRD's handover daemon lifecycle, not in protocol negotiation.

---

## 2. Incident Description

### 2.1 Symptoms

Users connecting via mstsc.exe observe:
- Successful credential entry at the GDM login screen
- Brief disconnection (expected -- this is the server redirect)
- Reconnection attempt followed by a **permanent black screen**
- Session timeout after 30-60 seconds with no desktop displayed

The failure was **complete** -- no RDP client connections succeeded. This was not an intermittent or timing-dependent issue; the handover daemon was being killed by gnome-settings-daemon before clients could reconnect.

### 2.2 Prior Reports

Investigation revealed that this was not a new or isolated problem. Related failures had been reported across multiple distributions over the preceding three years:

- **Red Hat Bugzilla #2189376** (April 2023): CredSSP/authentication failures connecting from Windows 10/11 clients to GNOME Remote Desktop on Fedora. Closed without resolution when Fedora reached end-of-life.
- **Launchpad #2065837** (May 2024): Black screen after RDP connection to Ubuntu with GNOME Remote Desktop. Confirmed by multiple users, no fix.
- **GNOME GitLab #244** (February 2025): mstsc unable to negotiate NTLMv1, requesting configuration options for NTLMv1/v2. Closed without a patch.

The reports all documented mstsc.exe failures but none had identified the root cause in GRD's handover daemon lifecycle.

### 2.3 Decision to Investigate and Patch

After encountering the failure firsthand and finding no existing fix, we filed [LP #2141992](https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2141992) documenting the issue for Ubuntu. Rather than wait for upstream resolution -- a path that had produced no results across three years and three distributions -- we decided to attempt the fix ourselves using agentic AI tooling, applying general troubleshooting methodology while relying on the AI for protocol-level and codebase knowledge we did not have (see Section 7).

---

## 3. Phase 1: Initial Analysis and Patch

The initial investigation, conducted with AI assistance, produced a five-bug analysis and a corresponding patch. The patch worked -- both mstsc.exe and FreeRDP clients connected successfully. However, as documented in Section 4, subsequent verification revealed that three of the five bugs were based on incorrect analysis. This section presents the initial findings as they were understood at the time, before correction.

### 3.1 Initial Bug Analysis (Five Hypothesized Bugs)

**Bug 1 (hypothesized) -- NLA-Only Security in SYSTEM Mode**: The AI analysis claimed that GRD's NLA-only security setting (`NlaSecurity=TRUE, TlsSecurity=FALSE`) in SYSTEM mode caused failures with mstsc.exe's CredSSP v6 implementation. The proposed fix added TLS as a fallback in SYSTEM mode, matching Windows RDS "Negotiate" defaults.

**Bug 2 (hypothesized) -- NLA Without SAM in Handover Mode**: The AI analysis claimed that the handover daemon "has no SAM database for NLA/NTLM auth," so NLA authentication would fail for any client that selected it. The proposed fix disabled NLA and enabled RDSTLS + TLS in handover mode.

**Bug 3 -- gsd-sharing Kills the Handover Daemon**: Journal log analysis revealed that gnome-settings-daemon's sharing plugin (`gsd-sharing`) stopped the handover service approximately 2 seconds after it started. The GDM greeter user had no configured connections in the Remote Desktop gsettings schema, so gsd-sharing called `StopUnit` on the handover service.

**Bug 4 -- One-Shot RequestHandover with No Retry**: The handover daemon called `RequestHandover` via D-Bus exactly once during initialization. If the system daemon hadn't processed the redirect yet, the call failed and was never retried.

**Bug 5 (self-inflicted) -- Retry Logic with Hard Limit**: The initial retry implementation for Bug 4 used a fixed limit of 30 retries. After 60 seconds, the daemon permanently stopped retrying. This was caught when connections still failed despite all other patches being applied.

### 3.2 The Initial Patch

The initial patch modified three files across two packages:

**`grd-session-rdp.c`** (gnome-remote-desktop): Per-mode security settings -- SYSTEM mode enabled TLS + NLA, HANDOVER mode enabled RDSTLS + TLS with NLA disabled.

**`grd-daemon-handover.c`** (gnome-remote-desktop): Retry logic for `RequestHandover` with two-phase retries (aggressive initial, then slow indefinite).

**`gsd-sharing-manager.c`** (gnome-settings-daemon): Conditional stop -- only stop the handover service when the system RDP daemon is not running.

### 3.3 Result: It Worked

After applying all patches:
- mstsc.exe connected successfully
- FreeRDP (xfreerdp3) connected successfully
- Session switching between clients worked
- The patch was published as `ppa:gerry9000/grd-mstsc-fix`, submitted as a Launchpad SRU, and posted to GNOME GitLab Issue #244

At this point, the investigation appeared complete. The five-bug analysis was internally consistent, the patch worked, and the narrative was compelling. But it was substantially wrong.

---

## 4. Phase 2: Adversarial Verification

### 4.1 The Red Flags

The verification phase began when the author started questioning specific claims in the AI-generated analysis:

- **"Is disabling NLA a big change? Wouldn't this affect all NLA users?"** -- The AI initially claimed it only affected handover mode. When pressed ("You're absolutely sure about NLA in handover mode?"), examination of the stock source code revealed that GRD creates a SAM database for handover mode at line 1231 via `grd_rdp_sam_create_sam_file(username, password)`. The AI's comment claiming "The handover daemon has no SAM database for NLA/NTLM auth" was factually wrong.

- **"Initializing to NULL sounds scary in a C program -- is that required for our fix?"** -- It wasn't. The change was reverted.

- **"We have 2 clean diffs to the original code? We are sure no superfluous fixes are currently in our baseline?"** -- This prompted a line-by-line review that removed several unnecessary changes.

Each question peeled back a layer of unverified assumption. The AI had generated plausible-sounding technical analysis that was internally consistent but factually incorrect.

### 4.2 Verification Against Source Code and Commit History

Four checks disproved the AI's protocol analysis:

1. **"No SAM database in handover mode"** -- The stock source creates one at line 1231 via `grd_rdp_sam_create_sam_file()` for all modes, including handover.

2. **"RDSTLS not offered in handover mode"** -- Commit [`ff5a85e`](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/ff5a85e) (November 2023) added RDSTLS to handover mode. Upstream has never disabled NLA alongside it -- the design is deliberately both-enabled.

3. **"NLA=FALSE needed to prevent fallback"** -- FreeRDP's server-side negotiation (`rdp_server_accept_nego()`) uses a strict priority chain: RDSTLS > NLA > TLS. Since the stock code enables RDSTLS and mstsc requests it after redirection, NLA is never selected. Our NLA=FALSE was a no-op.

4. **"Protecting against a handover crash"** -- Commit [`b1293fe`](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/b1293fe) (February 2026) fixes a crash in handover mode, but the code it fixes does not exist in GRD 49.0. Our change was not protecting against anything.

### 4.3 Iterative Diff Reduction

With the evidence from Section 4.2, we performed iterative diff reduction:

1. **Reverted session-rdp.c to stock** (removed NLA=FALSE, removed incorrect comment, restored stock setting order)
2. **Kept only daemon-handover.c changes** (retry logic) and **gsd-sharing-manager.c changes** (stop-kill fix)
3. **Rebuilt and retested**: mstsc.exe connected successfully, FreeRDP connected successfully, session switching worked

The session-rdp.c diff was reduced to **zero lines**. The stock authentication protocol code was correct all along.

---

## 5. Ground Truth: One Bug

### 5.1 Bug 1 -- gnome-settings-daemon Kills the Handover Daemon (GNOME gsd #931)

**File**: `plugins/sharing/gsd-sharing-manager.c` (gnome-settings-daemon)

The GNOME Settings Daemon's sharing plugin (`gsd-sharing`) monitors `gnome-remote-desktop-handover.service` and stops it when the current user has no `enabled-connections` in the Remote Desktop gsettings schema. In GDM greeter sessions, the greeter user has no configured connections, so gsd-sharing calls `StopUnit` on the handover service approximately 2 seconds after it starts.

Journal log evidence:

```
07:20:12 gnome-remote-desktop-daemon[2847]: [DaemonHandover] Starting handover daemon
07:20:14 systemd[2801]: gnome-remote-desktop-handover.service: Deactivated successfully.
```

The 2-second window between start and kill is consistent across all observed failures.

**Fix**: Condition the stop on whether the system RDP daemon is active. If the system daemon is running, the handover daemon is serving redirected sessions and should not be stopped regardless of the greeter user's gsettings:

```c
if (manager->sharing_status == GSD_SHARING_STATUS_OFFLINE)
  {
    if (!info->system_service_running)
      stop_assigned_service (manager, info);
  }
else
  {
    start_assigned_service (manager, info);
  }
```

Filed separately as [gnome-settings-daemon Issue #931](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/issues/931). Fix submitted as [MR !474](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474) targeting the gnome-49 branch.

The bug affects GNOME 46 through 49 across multiple distributions (see Section 6.4). On `main` (GNOME 50), the bug was resolved differently by a full refactor that decouples assigned services from network status entirely. Our MR provides the minimal backport for stable branches.

### 5.2 Eliminated Bug -- RequestHandover Retry (Previously Bug 2)

The initial analysis added retry logic to the handover daemon's `RequestHandover` D-Bus call. After the gsd-sharing fix was in place, testing showed `RequestHandover` succeeded on the first try in every scenario -- normal connections, concurrent sessions, crash-restart recovery. The retry code was removed. Zero changes to gnome-remote-desktop are required.

### 5.3 The Actual Failure Mode

With the retry logic removed, the failure mode is simpler than initially theorized:

1. The handover daemon starts and calls `RequestHandover` -- this succeeds immediately
2. Approximately 2 seconds later, gsd-sharing kills the daemon (Bug 1)
3. The client completes its redirect and attempts to connect to a daemon that no longer exists

There is only one bug, and it is in gnome-settings-daemon.

A successful connection on stock GRD requires: the client to reconnect within the narrow window after the handover daemon's single `RequestHandover` call succeeds AND before gsd-sharing kills the daemon. Under normal network conditions, this window is effectively zero.

### 5.4 What Was Wrong in the Initial Analysis

Three of the five initially hypothesized bugs were based on incorrect AI-generated analysis:

| Initial Claim | Reality | How Discovered |
|---------------|---------|----------------|
| "NLA-only in SYSTEM mode causes CredSSP v6 failures" | NLA in system mode works correctly; it's the standard pre-login auth mechanism | Source code review: stock code is by design |
| "Handover daemon has no SAM database" | SAM file is created at line 1231 via `grd_rdp_sam_create_sam_file()` for all modes | Reading the stock source code |
| "RDSTLS not offered in handover mode" | RDSTLS has been enabled in handover mode since Nov 2023 (commit `ff5a85e`) | Git blame on GNOME repository |
| "NLA=FALSE needed to prevent fallback to broken NLA" | RDSTLS always takes priority over NLA in FreeRDP's server negotiation; NLA=FALSE is a no-op | FreeRDP source analysis of `rdp_server_accept_nego()` |
| "Retry limit gives up after 60s" | Self-inflicted by our own retry logic; the entire retry was later removed as unnecessary | Iterative reduction |

The initial patch worked because it included the one real fix (gsd-sharing guard) alongside four unnecessary changes -- NLA=FALSE, TLS=TRUE, system mode protocol changes, and RequestHandover retry logic. The unnecessary changes were harmless no-ops or unreproducible defensive code. But they were presented with fabricated or unverifiable justifications that did not survive verification.

---

## 6. Remediation

### 6.1 Final Patch Summary

The verified fix is a single change in one package:

| Package | File | Change |
|---------|------|--------|
| gnome-settings-daemon | `plugins/sharing/gsd-sharing-manager.c` | Don't stop handover service when system RDP daemon is active |

**Zero changes to gnome-remote-desktop.** The stock authentication protocol code and handover daemon are correct as-is.

### 6.2 Security Considerations

**No authentication protocol changes**: The verified fix does not modify any security protocol settings. NLA remains enabled in all modes. RDSTLS remains enabled in handover mode (stock behavior since GNOME 46). No TLS fallbacks are added. No changes to gnome-remote-desktop at all.

**gsd-sharing conditional stop**: The fix only prevents stopping the handover daemon when the system RDP daemon is active. When the system daemon is not running (no RDP sessions in progress), gsd-sharing's stop behavior is unchanged. The guard mirrors the existing check in the start path (`start_assigned_service` at line 289).

### 6.3 Deployment

**Ubuntu PPA** (immediate fix for Ubuntu 25.10):

```bash
sudo add-apt-repository ppa:gerry9000/grd-mstsc-fix
sudo apt update && sudo apt upgrade gnome-settings-daemon
sudo systemctl restart gnome-remote-desktop
```

**Launchpad SRU**: Debdiff for gnome-settings-daemon 49.0-1ubuntu3.1 submitted to [LP #2141992](https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2141992).

**GNOME GitLab**: Fix submitted as [MR !474](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474) targeting the gnome-49 branch. The gsd-sharing bug is tracked as [Issue #931](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/issues/931).

### 6.4 Affected Versions

The bug was introduced in GNOME 46 (commit [`0bfc6081`](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/commit/0bfc6081), November 2023) and exists in every stable branch through GNOME 49. It is fixed on `main` (GNOME 50, not yet released) by a different approach -- commit [`65b257b6`](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/commit/65b257b6) (October 2025) which removes the dependency between assigned services and network status entirely.

| GNOME Version | Affected | Fix Available | Distributions |
|---------------|----------|---------------|---------------|
| GNOME 46 | Yes | Not yet | Ubuntu 24.04 LTS, Debian 13 |
| GNOME 47 | Yes | Not yet | Ubuntu 24.10, Fedora 41 |
| GNOME 48 | Yes | Not yet | Ubuntu 25.04, Fedora 42 |
| GNOME 49 | Yes | MR !474 | Ubuntu 25.10, Fedora 43, Arch, openSUSE TW |
| GNOME 50 | No | 65b257b6 | Not yet released |

The scope of the bug is significant. Ubuntu 24.04 LTS (GNOME 46) has a five-year support window and ships with the same vulnerable `gsd_sharing_manager_sync_assigned_services()` function. Any distribution running GNOME 46-49 with system-mode RDP is affected.

---

## 7. Methodology and Lessons

### 7.1 Investigation Tools

The analysis used:
- **journalctl** with UID filtering (`_UID=60578`) to isolate GDM greeter session logs
- **systemd service tracing** to identify gsd-sharing as the actor stopping the handover service
- **FreeRDP debug logging** (`WLOG_LEVEL=DEBUG`) to observe protocol negotiation in real time
- **Source code diffing** to track changes and reduce patches to minimum necessary
- **Git blame and commit history** on the GNOME GitLab repository
- **Agentic AI tooling** (Claude Code) for codebase navigation, root cause analysis, and patch development

### 7.2 Adversarial Verification Techniques

The verification phase used five techniques to separate fact from fabrication:

**Source code investigation**: The AI claimed "the handover daemon has no SAM database." Line 1231 of the stock source creates one via `grd_rdp_sam_create_sam_file()`.

**Git blame and commit history**: Commit `ff5a85e` (November 2023) confirmed RDSTLS was already enabled in handover mode and that upstream deliberately kept NLA enabled alongside it.

**Upstream bug tracker review**: Commit `b1293fe` (February 2026) fixed a crash in handover mode, but the code it fixes does not exist in 49.0 -- preventing us from keeping an unnecessary "protective" change.

**Protocol implementation analysis**: FreeRDP's `rdp_server_accept_nego()` confirmed RDSTLS always takes priority over NLA. Debug logs showed mstsc requests RDSTLS after redirection. NLA=FALSE was a no-op.

**Iterative diff reduction**: Removing each unsupported change and retesting. The session-rdp.c diff went from 15 lines to zero; the daemon-handover.c diff followed. If removing a change doesn't break anything, the change was unnecessary.

### 7.3 AI-Assisted Security Research: Power and Pitfalls

The author of this paper is a cybersecurity professional, not a C developer. The entire workflow -- from initial triage through root cause analysis to working patches -- was conducted using agentic AI tools directed by system administration experience and troubleshooting methodology.

The AI navigated a 50,000+ line C codebase, identified the gsd-sharing lifecycle issue through journal log correlation, generated syntactically correct patches, and handled Debian packaging mechanics. Without it, this investigation would not have been possible.

But the AI also generated an internally consistent five-bug narrative where only one bug required a fix. It fabricated identifiers (a flag name that doesn't exist in any RDP specification), made incorrect claims about the codebase (asserting the absence of a SAM database that was demonstrably present), and proposed well-engineered code that solved a problem that couldn't be reproduced. Every claim sounded plausible. The patch compiled and worked. The analysis was wrong.

The errors were caught not by technical expertise in C or RDP, but by security-minded questions: "Why is NLA in the authentication stack -- what are the security ramifications of disabling it?", "You're absolutely sure that flag exists?", "Are there superfluous fixes in our baseline?" Each question led to checking the actual source, the actual commit history, the actual protocol implementation -- and each check revealed incorrect analysis. Asking about NLA's security role exposed a fabricated flag and an unnecessary change. Asking about superfluous fixes led to iterative diff reduction that eliminated four of five proposed changes. The initial patch resolved the problem we set out to fix. Continued research, informed by what we learned building that patch, found the root cause and a more appropriate fix.

### 7.4 Implications for AI-Assisted Development

This investigation produced a working fix for a real bug that had gone unresolved for three years. That outcome matters. The AI tooling enabled a security professional without C development experience to diagnose and patch a complex system -- something that would have been impossible without it.

But the investigation also produced fabricated technical claims, unnecessary code changes, and an incorrect root cause analysis. These were caught only because the human applied consistent skepticism and verification against primary sources: the actual source code, the actual commit history, the actual protocol implementation.

The takeaway is not "don't use AI tooling" -- it's that AI-assisted security research requires the same adversarial mindset that security professionals already apply to other domains. Trust but verify. Check the source. Question plausible narratives. Reduce to the minimum and test.

A companion training module walks through the AI-assisted investigation process step by step. It covers the workflow hardening that made this investigation possible: project-level verification rules (`CLAUDE.md`) that require grepping before referencing any identifier, skills (`.agents/skills/`) like `/verify-claim` and `/review-diff` that enforce source-level checks before any technical assertion or patch submission, and the discipline of classifying every finding as VERIFIED or INFERRED. The module also catalogs the hallucination patterns encountered in this investigation and the specific techniques that caught them. It is available at [`Gerry9000/training-devsecops-ai-agents`](https://github.com/Gerry9000/training-devsecops-ai-agents/tree/main/modules/10-rdp-protocol-forensics).

---

## References

1. Microsoft, "[MS-RDPBCGR]: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting," https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr
2. Microsoft, "[MS-RDPBCGR]: RDSTLS Security," https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/83d1186d-cab6-4ad8-8c5f-203f95e192aa
3. GNOME, "gnome-remote-desktop source," GNOME GitLab
4. GNOME Remote Desktop Issue #244, https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/issues/244
5. gnome-settings-daemon Issue #931, https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/issues/931
6. Launchpad Bug #2141992, https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2141992
7. Red Hat Bugzilla #2189376, https://bugzilla.redhat.com/show_bug.cgi?id=2189376
8. Launchpad Bug #2065837, https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2065837
9. FreeRDP, "Server-side protocol negotiation," `libfreerdp/core/connection.c`, `rdp_server_accept_nego()`
10. GNOME commit ff5a85e, "session-rdp: Use RDSTLS security on daemon-handover," November 2023, https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/ff5a85e
11. GNOME commit b1293fe, "session-rdp: Don't check for authentication methods on daemon-handover," February 2026, https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/b1293fe
12. GNOME commit 65b257b6, "sharing: Start assigned services without depending on network," October 2025, https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/commit/65b257b6
13. gnome-settings-daemon MR !474, https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474
