# Wazuh-Detection-Lab-with-Atomic-Red-Team
Hands-on cybersecurity lab using Wazuh SIEM/XDR to detect simulated MITRE ATT&amp;CK techniques executed with Atomic Red Team, showcasing real-world threat detection and incident response skills.

# Introduction (English)
This repository provides a complete *Wazuh detection lab* to simulate adversary tactics and techniques mapped to the MITRE ATT&CK framework. Using Atomic Red Team tests alongside a Wazuh SIEM/XDR deployment, the lab demonstrates how to detect malicious behaviors on a Windows endpoint by leveraging detailed log telemetry (e.g. from Sysmon) and Wazuh’s analysis engine. The content is presented in both English and Spanish for a global reach.

# What is Wazuh and Sysmon?
Wazuh is an open-source security platform (SIEM/XDR) that can collect and analyze logs from endpoints. Sysmon (System Monitor) is a Windows service from Microsoft Sysinternals that records detailed system activity (process creations, network connections, file events, registry changes, etc.). By forwarding Sysmon logs to Wazuh, we gain high-fidelity visibility into system behavior, helping to spot suspicious actions, persistence mechanisms, and post-exploitation activity.

# What is Atomic Red Team?
Atomic Red Team is an open-source library of lightweight scripts that simulate real attack techniques as defined by MITRE ATT&CK. In this lab, Atomic Red Team was used to execute benign test behaviours on the Windows Machine that resemble tactics like [Simulating] phishing, credential dumping, and more. This allow us to safely validate that Wazuh can detect and alert on these activities without any harm.

# Recomendations Before Using Atomic Red Team
1. You should never run atomic test on systems you don't own or have explicit permission to test (This includes, No testing on public infrastructure and No testing on third-party platforms.)
2. Atomic Red Team is best used in isolated and controlled test systems or virtual environments.
(your telemetry is easier to analyze and you won't impact any business operation)
3. Avoid real user data in test:
   -Some Atomic Test might touch
   *Local Accounts
   *File Systems
   * Event Logs
   * Network Connections
  4. Document Everything.
     * The documentation is useful for reporting, building repeatable processes, audit trails, and also for recovering from a possible side effect caused by the test.
    


# Prerequisites (English)
Before setting up the lab, ensure you have the following components and tools ready:

Windows 10/11 Endpoint – a Windows host (virtual machine recommended) to act as the target system where attacks will be simulated.

Wazuh Manager & Agent – a running Wazuh Manager server, and the Wazuh Agent installed on the Windows endpoint (they should be connected). This lab assumes you have a working Wazuh 4.x environment.

Sysmon – the Sysinternals Sysmon tool (Sysmon64.exe) downloaded, and a Sysmon configuration XML (you can use a public config such as SwiftOnSecurity or Olaf Hartong’s sysmon-modular project).

Administrator Privileges – ability to run PowerShell/Command Prompt as admin on the Windows VM (needed to install Sysmon and run certain simulation steps).

Internet Access – the Windows VM should have internet (or at least access to the Atomic Red Team script repository) to download necessary tools.

Basic Knowledge – some familiarity with Windows logging and Wazuh configuration will help in following the steps.

(Note: It’s highly recommended to use an isolated lab VM or snapshot for these simulations and not a production system, as the simulated attacks, while not truly malicious, can make changes like creating accounts or scheduled tasks.)

# Lab Setup (English)
Follow These steps to configure the lab environment:
1. Install and Configure Sysmon on the Windows Endpoint

Download Sysmon: Get the latest Sysmon from Microsoft’s Sysinternals site. Extract the ZIP (which contains Sysmon.exe / Sysmon64.exe).

Download a Sysmon config: Use a recommended Sysmon configuration file that defines what events to log. For example, download the SwiftOnSecurity Sysmon config or Olaf Hartong’s sysmon-modular config. Save the config as sysmonconfig.xml on the Windows host.

Install Sysmon with config: Open PowerShell as Administrator and run the Sysmon install command:
```
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```
This installs Sysmon as a service with the given configuration. You should see a message that Sysmon installed successfully.

Verify Sysmon is logging: Open Event Viewer (Windows Logs → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational). You should see Sysmon events being recorded. For example, Event ID 1 (process creation) events whenever a process launches, Event ID 3 for network connections, etc. Ensure events are appearing here, as Wazuh will pull from this log.

2. Configure the Wazuh Agent to Collect Sysmon Events
Enable Sysmon log collection: On the Windows Endpoint, edit the Wazuh agent configuration file (typically: C:\Program Files (x86)\ossec-agent\ossec.conf). Within the <ossec_config> section, add a new <localfile> entry to subscribe to the Sysmon event log, like this:
```
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```
this tells the Wazuh Agent to continously read the Sysmon Operational log channel.

Restart the agent: Save the config and restart the Wazuh agent service on Powershell:
Restart-Service -Name WazuhAgent (You can use TAB to autocomplete the wazuh service name just in case it is named different). The agent will now start sending Sysmon events to the Wazuh Manager.

Confirm on Manager: Verify from the Wazuh Manager that Sysmon events are being received. You can search for events with sysmon data in Wazuh's alerts to ensure the pipeline is working.

3. Add Custom Wazuh Rules for MITRE Techniques (Optional)
Wazuh comes with many built-in rules that detect common events (and even maps some to MITRE ATT&CK tactics). So in this case we won't be creating any custom rules. If you want to create custom rules you are free to do so.

# Attack Simulation with Atomic Red Team (English)
With the logging and detection rules in place, we can simulate various attacks techniques on the Windows VM using Atomic Red Team. All test should be run on the Windows Endpoint (with Admin rights) and will not harm the system, but they do produce events that resemble real attacks. Remember to only run these in your lab VM (Not on actual production machines).

1. Installing Atomic Red Team
Download and Install Atomic Red Team: On the Windows VM, open Powershell as Administrator and execute the following:
```
git clone https://github.com/redcanaryco/atomic-red-team.git
```
This will download the Atomic Red Team Powershell module and the library of tomic tests to C:\AtomicRedTeam\ (by default). You should see it fetching a lot of technique scripts.

Import the module (if needed): If the install doesn't auto-import, run:
```
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
```
This makes the Invoke-AtomicTest command available in your session.

Verify installation: You can test by running something like Get-AtomicTechnique -List | select TechniqueID, Name -First 5 to list some techniques, or Invoke-AtomicTest T1003.001 -ShowDetailsBrief to see details of a specific atomic test (for LSASS dumping, for example).

2. Simulating MITRE ATT&CK Techniques
We will run a series of atomic tests corresponding to different MITRE ATT&CK techniques across various tactics. Each test will perform a small action on the system that mimics an attacker behavior, allowing us to observe if Wazuh logs or alerts on it. Below are examples of techniques you can simulate (with their MITRE technique IDs):



