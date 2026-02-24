# References

## Upstream Submissions
- [gnome-settings-daemon MR !474](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/merge_requests/474) -- Fix targeting gnome-49 branch
- [gnome-settings-daemon #931](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/issues/931) -- gsd-sharing stops handover service in greeter sessions

## Related Issues
- [GNOME Remote Desktop #244](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/issues/244) -- mstsc.exe handover fails on headless VMs
- [Red Hat Bugzilla #2189376](https://bugzilla.redhat.com/show_bug.cgi?id=2189376) -- CredSSP failures on Fedora (2023)

## Ubuntu
- [Launchpad Bug #2141992](https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2141992) -- SRU submission with gnome-settings-daemon debdiff
- [Launchpad Bug #2065837](https://bugs.launchpad.net/ubuntu/+source/gnome-remote-desktop/+bug/2065837) -- Black screen after RDP connection (2024)
- [PPA: ppa:gerry9000/grd-mstsc-fix](https://launchpad.net/~gerry9000/+archive/ubuntu/grd-mstsc-fix)

## Key Commits
- [ff5a85e](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/ff5a85e) -- "session-rdp: Use RDSTLS security on daemon-handover" (Nov 2023)
- [0bfc6081](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/commit/0bfc6081) -- Introduced handover code in gsd-sharing (Nov 2023, bug introduced)
- [65b257b6](https://gitlab.gnome.org/GNOME/gnome-settings-daemon/-/commit/65b257b6) -- "sharing: Start assigned services without depending on network" (Oct 2025, fix on main)
- [b1293fe](https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/commit/b1293fe) -- "session-rdp: Don't check for authentication methods on daemon-handover" (Feb 2026)

## Protocol Specifications
- [MS-RDPBCGR: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/)
- [MS-RDPBCGR: RDSTLS Security](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/83d1186d-cab6-4ad8-8c5f-203f95e192aa)
- [MS-CSSP: Credential Security Support Provider (CredSSP) Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/)

## Source Code
- [GNOME Remote Desktop](https://gitlab.gnome.org/GNOME/gnome-remote-desktop) -- GNOME GitLab
- [GNOME Settings Daemon](https://gitlab.gnome.org/GNOME/gnome-settings-daemon) -- GNOME GitLab
- [FreeRDP](https://github.com/FreeRDP/FreeRDP) -- Server-side protocol negotiation in `libfreerdp/core/connection.c`
