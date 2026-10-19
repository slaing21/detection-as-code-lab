# Lab Build Guide

This lab build guide reflects the environment as actually built, please confirm versions against your own install.

**Definition of done:** the Wazuh dashboard shows the endpoint agent as **Active**, a Sysmon Event ID 1 from that endpoint is visible in Wazuh, both VMs have clean snapshots, and the configs used are committed to this repo.

## Host Prerequisites

- [VirtualBox 7.1+](https://www.virtualbox.org/wiki/Downloads)
- **Disable Virtualization-Based Security and the Windows hypervisor.**

## Network Design

Host-only network `192.168.56.0/24`, isolated:

| VM | Host-only IP | Role |
|---|---|---|
| `siem-01` | `192.168.56.10` (static) | Wazuh manager + indexer + dashboard |
| `win11-endpoint` | `192.168.56.20` (static) | Sysmon + Wazuh agent + Atomic Red Team |

A **temporary NAT adapter** on the endpoint is used only to stage prerequisites and Atomic Red Team, then **disconnected** and the VM re-snapshotted.

## SIEM VM — Ubuntu Server + Wazuh 4.14

1. Create the Ubuntu Server SIEM VM in VirtualBox using an [Ubuntu Server Image](https://ubuntu.com/download/server). Network Adapter 1 = NAT, Network Adapter 2 = Host-only
2. Ubuntu Server. **Size `ubuntu-lv` to the full disk at install**
3. Static IP via netplan
4. `sudo apt update && sudo apt upgrade -y && sudo reboot`
5. Install Wazuh:
   ```bash
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a
   ```
6. Browse to `https://192.168.56.10`, accept the self-signed cert, log in with the admin password given during the Wazuh Install.
7. Snapshot `siem-01-clean-wazuh`.

## Endpoint VM — Windows 11

1. Create the Windows 11 Endpoint VM in VirtualBox using a [Windows 11 ISO](https://www.microsoft.com/en-us/software-download/windows11). Network Adapter 1 = NAT (temporary), Network Adapter 2 = Host-only. Run Windows Update once, snapshot `ep-01-clean-os`.
2. **Sysmon** with the committed config:
   ```powershell
   Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
   ```
3. **Wazuh agent:** Dashboard -> Agents -> Deploy new agent -> Windows, server `192.168.56.10`, name `win11-endpoint`. Run the generated command as Admin, then `NET START WazuhSvc`.
4. Add the Sysmon channel to the agent config (`lab/endpoint/ossec-conf-localfile-addition.conf`) and restart the agent.
5. **Atomic Red Team** (while NAT is connected): `Set-ExecutionPolicy RemoteSigned`, install the NuGet provider, trust PSGallery, then install `invoke-atomicredteam`. Add a Defender exclusion for the atomics folder.
6. Disconnect the NAT adapter. Confirm the agent still reports its **host-only** IP `192.168.56.20`. 
7. Snapshot `ep-02-baseline`.

## Troubleshooting

| Symptom | Likely Causes |
|---|---|
| Agent "Never connected" | wrong manager IP; firewall blocking outbound 1514/1515; `WazuhSvc` not started |
| Agent "Disconnected" after isolation | disconnected the host-only adapter instead of NAT |
| Sysmon events in Event Viewer, nothing in Wazuh | `<localfile>` missing/misspelled; agent not restarted; built-in rules are level 0 |
| Dashboard unreachable from host | SIEM IP changed (set it static); or just the cert warning |
| Windows installer: "PC doesn't meet requirements" | EFI / TPM 2.0 / Secure Boot not enabled in VM settings |
| Wazuh installer aborts on memory | give the VM more RAM |