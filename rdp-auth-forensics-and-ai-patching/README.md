# RDP Authentication Forensics and AI-Assisted Patching of GNOME Remote Desktop 49.0

## White Paper

GNOME Remote Desktop 49.0 fails to complete RDP sessions with Windows mstsc.exe on headless VMs -- a black screen after login, reported across multiple distributions since 2023 without resolution. Using agentic AI tooling, a cybersecurity professional with no prior C development experience investigated the root cause and developed a working patch. The AI-assisted analysis initially identified five bugs, but adversarial verification proved only one required a fix -- in a different package than originally patched. The progression from a working five-bug patch to a verified single-line fix in gnome-settings-daemon demonstrates both what AI-assisted security research makes possible and why adversarial verification of AI output is essential.

**Author**: Gerry Burde
**Date**: February 2026
**Version**: 1.0

### Topics
- AI-assisted security research and adversarial verification of AI output
- Service lifecycle forensics and root cause analysis
- RDP authentication protocol analysis (NLA, CredSSP, RDSTLS)
- Upstream patch submission workflow (PPA, SRU, GNOME GitLab MR)

### Contents
- [`paper/paper.md`](paper/paper.md) -- The white paper (v1.0)
- [`patches/`](patches/) -- All patches from the investigation, including superseded Phase 1 patches and the final verified fix

### Patches

| File | Phase | Description |
|------|-------|-------------|
| `gnome-settings-daemon_49.0-1ubuntu3.1.debdiff` | Final | The verified fix -- one guard condition in gsd-sharing-manager.c |
| `gnome-remote-desktop_lp2141992.debdiff` | Phase 1 | Initial 4-bug debdiff (gnome-remote-desktop, superseded) |
| `gnome-remote-desktop_49.0-0ubuntu1.3.debdiff` | Phase 1 | Revised GRD debdiff with two-phase retry (superseded) |
| `ppa-lp-2141992-fix-mstsc-handover-negotiation.patch` | Phase 1 | DEP-3 quilt patch for PPA (gnome-remote-desktop, superseded) |
| `upstream-fix-mstsc-handover-negotiation.patch` | Phase 1 | git-format patch posted to GNOME #244 (superseded) |

Phase 1 patches are included for reference -- the paper documents the progression from five hypothesized bugs to one verified fix, and these patches are part of that story.

### Related
- [MR !474](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474) -- Upstream fix targeting gnome-49 branch
- [gnome-settings-daemon #931](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/issues/931) -- gsd-sharing bug report
- [GNOME Remote Desktop #244](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/issues/244) -- Original issue discussion
- [LP #2141992](https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2141992) -- Ubuntu bug report and SRU submission
- PPA: `ppa:gerry9000/grd-mstsc-fix`

### Companion Training Module
A step-by-step training module covering the AI-assisted investigation process, verification techniques, and hallucination patterns is available at [`training-devsecops-ai-agents/modules/10-rdp-protocol-forensics/`](https://github.com/Gerry9000/training-devsecops-ai-agents/tree/main/modules/10-rdp-protocol-forensics).
