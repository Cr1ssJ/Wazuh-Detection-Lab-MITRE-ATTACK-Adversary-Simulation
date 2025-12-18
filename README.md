# Wazuh-Detection-Lab-with-Atomic-Red-Team
Hands-on cybersecurity lab using Wazuh SIEM/XDR to detect simulated MITRE ATT&amp;CK techniques executed with Atomic Red Team, showcasing real-world threat detection and incident response skills.

# Introduction
This repository provides a complete *Wazuh detection lab* to simulate adversary tactics and techniques mapped to the MITRE ATT&CK framework. Using Atomic Red Team tests alongside a Wazuh SIEM/XDR deployment, the lab demonstrates how to detect malicious behaviors on a Windows endpoint by leveraging detailed log telemetry (e.g. from Sysmon) and Wazuh’s analysis engine. The content is presented in both English and Spanish for a global reach.

# What is Wazuh and Sysmon?
Wazuh is an open-source security platform (SIEM/XDR) that can collect and analyze logs from endpoints. Sysmon (System Monitor) is a Windows service from Microsoft Sysinternals that records detailed system activity (process creations, network connections, file events, registry changes, etc.). By forwarding Sysmon logs to Wazuh, we gain high-fidelity visibility into system behavior, helping to spot suspicious actions, persistence mechanisms, and post-exploitation activity.

# What is Atomic Red Team?
Atomic Red Team is an open-source library of lightweight scripts that simulate real attack techniques as defined by MITRE ATT&CK. In this lab, Atomic Red Team was used to execute benign test behaviours on the Windows Machine that resemble tactics like [Simulating] phishing, credential dumping, and more. This allow us to safely validate that Wazuh can detect and alert on these activities without any harm.

# Recomendations Before Using Atomic Red Team
1. You should never run atomic test on systems you don't own or have explicit permission to test (This includes, No testing on public infrastructure and No testing on third-party platforms.)
2. Atomic Red Team is best used in isolated and controlled test systems or virtual environments.
(your telemetry is easier to analyze and you won't impact any business operation)
3. Avoid real user data in test.
   Some Atomic Test might touch:
   * Local Accounts
   * File Systems
   * Event Logs
   * Network Connections
  4. Document Everything.
     * The documentation is useful for reporting, building repeatable processes, audit trails, and also for recovering from a possible side effect caused by the test.

The documentation can include:
   * The technique ID and test name.
   * When and where it was executed.
   * Who authorized it.
   * What arguments or configurations were used.
   * And the results of the test.

# Prerequisites
Before setting up the lab, ensure you have the following components and tools ready:

Windows 10/11 Endpoint – a Windows host (virtual machine recommended) to act as the target system where attacks will be simulated.

PowerShell 5.0+ or PowerShell Core

Wazuh Manager & Agent – a running Wazuh Manager server, and the Wazuh Agent installed on the Windows endpoint (they should be connected). This lab assumes you have a working Wazuh 4.x environment.

Sysmon – the Sysinternals Sysmon tool (Sysmon64.exe) downloaded, and a Sysmon configuration XML (you can use a public config such as SwiftOnSecurity or Olaf Hartong’s sysmon-modular project).

Administrator Privileges – ability to run PowerShell/Command Prompt as admin on the Windows VM (needed to install Sysmon and run certain simulation steps).

Internet Access – the Windows VM should have internet (or at least access to the Atomic Red Team script repository) to download necessary tools.

Basic Knowledge – some familiarity with Windows logging and Wazuh configuration will help in following the steps.

(Note: It’s highly recommended to use an isolated lab VM or snapshot for these simulations and not a production system, as the simulated attacks, while not truly malicious, can make changes like creating accounts or scheduled tasks.)

# Lab Setup
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

# Attack Simulation with Atomic Red Team
With the logging and detection rules in place, we can simulate various attacks techniques on the Windows VM using Atomic Red Team. All test should be run on the Windows Endpoint (with Admin rights) and will not harm the system, but they do produce events that resemble real attacks. Remember to only run these in your lab VM (Not on actual production machines).

1. Installing Atomic Red Team
Download and Install Atomic Red Team: On the Windows VM, open Powershell as Administrator and execute the following:
```
git clone https://github.com/redcanaryco/atomic-red-team.git
```
This will download the Atomic Red Team Powershell module and the library of tomic tests to C:\AtomicRedTeam\ (by default).
ou should see it fetching a lot of technique scripts.

Import the module (if needed): If the install doesn't auto-import, run:
```
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
```
This makes the Invoke-AtomicTest command available in your session.

Verify installation: You can test by running something like Get-AtomicTechnique -List | select TechniqueID, Name -First 5 to list some techniques, or Invoke-AtomicTest T1003.001 -ShowDetailsBrief to see details of a specific atomic test (for LSASS dumping, for example).

2. Simulating MITRE ATT&CK Techniques
We will run a series of atomic tests corresponding to different MITRE ATT&CK techniques across various tactics. Each test will perform a small action on the system that mimics an attacker behavior, allowing us to observe if Wazuh logs or alerts on it. Below are examples of techniques you can simulate (with their MITRE technique IDs):

   - T1087.001 - Account Discovery (Local Accounts): Simulates an  adversary enumerating local user accounts on the machine (using net user). Atomic Red Team will run commands to list local accounts on the system. This falls under Discovery Tactics (querying system for user accounts)

   - T1566.001 - Phishing: Spearphishing Attachment: Simulates a scenario where a user opens a malicious email attachment. The Atomic test may create or execute harmless file to imitate the outcome of a spear-phishing email (for example, launching a payload). This represents the Initial Access tactic.
  
   - T1078.001 - Valid Accounts (Local Account): Simulates use of a valid account for persistence or lateral movement. For example, the test might create a new local user account or use existing credentials. This can cover Persistence (creating backdoor accounts) and Defense Evasion (using legitimate credentials).
  
   - T1003.001 – OS Credential Dumping: LSASS Memory: Simulates dumping credentials from the LSASS process memory. The atomic test will attempt to access lsass.exe’s memory (without actually stealing passwords), triggering security events. This exercise demonstrates the Credential Access tactic.
  
   - T1069.001 – Permission Groups Discovery: Local Groups: Simulates an attacker enumerating local administrative groups and their members. The atomic test will run a command (like net localgroup administrators) to list group memberships. This is under the Discovery tactic.
  
   - T1020 – Automated Exfiltration: Simulates data exfiltration from the system. For example, the atomic may compress files and simulate sending them out or moving data to a staging location. This represents the Exfiltration tactic.

In order to execute these test, use the *Invoke-AtomicTest* cmdlet with the technique ID. For instance, to run the Local Account Discovery test:

```
Invoke-AtomicTest T1087.001
```

You will see Atomic Red Team executing the steps (it might run one or more commands or scripts depending on the test). It should print output indicating success or what it did. Similarly, run the other tests one by one:

```
Invoke-AtomicTest T1566.001   # Spearphishing Attachment
Invoke-AtomicTest T1078.001   # Valid Accounts (create/use local account)
Invoke-AtomicTest T1003.001   # LSASS Credential Dump attempt
Invoke-AtomicTest T1069.001   # Local Groups Enumeration
Invoke-AtomicTest T1020      # Automated Exfiltration
```
Here are some test I executed:
<img width="960" height="403" alt="Captura de pantalla 2025-12-13 212045" src="https://github.com/user-attachments/assets/85fda107-b377-4c23-b427-384cbf222a69" />

<img width="669" height="447" alt="Captura de pantalla 2025-12-13 173053" src="https://github.com/user-attachments/assets/8751918f-c84c-42be-96fe-8192f6b287f4" />

<img width="804" height="272" alt="Captura de pantalla 2025-12-14 075436" src="https://github.com/user-attachments/assets/d248d1dd-011e-4059-9db2-463c427bccf0" />

<img width="911" height="264" alt="Captura de pantalla 2025-12-14 090821" src="https://github.com/user-attachments/assets/5dd87a70-15f4-41eb-be03-5380a4b8bea0" />

<img width="818" height="481" alt="Captura de pantalla 2025-12-14 205910" src="https://github.com/user-attachments/assets/e31063ed-3a95-4e24-bb8f-d187d788a18f" />

<img width="912" height="142" alt="Captura de pantalla 2025-12-15 010726" src="https://github.com/user-attachments/assets/e26cd7b8-8b16-483a-9199-e967b7be1e15" />


Each Invoke-AtomicTest call will perform the specific technique simulation. For example, the LSASS dump test will likely use a tool or method to open a handle to lsass.exe (which should trigger a Sysmon Event ID 10 for process access). The exfiltration test might create dummy data and attempt to copy it out. No actual malicious payloads are used. these tests are benign, though they mimic real attack footprints.


# Cleanup
Many of these tests make temporary changes (like creating a user or scheduled task, or dropping a file). Atomic Red Team usually provides a cleanup command or reverses changes at the end of the test. However, it’s good practice to manually revert any changes. For instance, if a new user was created or a scheduled task added, you should remove them after testing. You can also take a VM snapshot before the tests and rollback later for a pristine state. For example you can run:
```
Invoke-AtomicTest <Technique> -Cleanup
Remove-Item $env:TEMP\lsass_*.dmp -ErrorAction Ignore
```
In order to cleanup those temporary files, created users or scheduled task.
Refer to Atomic Red Team’s documentation for specific cleanup steps for each technique (often shown with -Cleanup flags or in test details).

# Detection and Results
After running the atomic simulations, we can analyze how Wazuh detects these activities.  Because we configured the Wazuh agent to send detailed Sysmon logs and we have the Wazuh's built-in rules, we should see alerts corresponding to several simulared techniques.

Here are the expected outcomes and how to observe them:

   - Wazuh Alerts in Dashboard: Open Wazuh Dashboard and navigate to Security Events or MITRE ATT&CK view. Wazuh's MITRE ATT&CK module can map alerts to tactics and techniques. You should see alerts corresponding to the techniques executed. For example, the MITRE view might highlight T1003 for Credential Access, T1087 for Discovery, etc, if those alerts were generated.

   - Account Creation (T1078/T1136): When the atomic test created a new user, Windows generated event logs ( for example, Event ID 4720 in the Security log). Wazuh should have captured this and triggered an alert like “User account created” (rule 60109). In the alert data, you may find the new username. This indicates Persistence via Valid Accounts was simulated.

   - LSASS Access (T1003.001): The LSASS memory access attempt triggers Sysmon Event ID 10. Wazuh’s built-in rule 92900 is designed to detect this, and our custom rule 110003 as well. You should see an alert about a process accessing LSASS (often message like “LSASS process was accessed by [ProcessName]… possible credential dump”). The alert will be tagged with MITRE T1003.001 (either by built-in mapping or if you have created a custom rule). This confirms the credential dumping simulation was caught. According to Wazuh documentation, rule 92900 and 92403 are default rules that cover unauthorized LSASS access attempts

   - Phishing/Spearphishing (T1566.001): This one might not generate a very explicit alert unless the simulated payload triggers something. Check the Sysmon Process Create events around the time you ran the spearphishing test. For example, if you created a custom rule you may see the explicit alert or a related Wazuh rule might have fired. Also, Windows Defender or other built-in tools might log events. In our lab, focus on Sysmon logs and Wazuh default configuration and see if any suspicious process executions were captured (like a Word or script process).

   - Local Groups Enumeration (T1069.001): We can look for process creation events for the commands run (like net.exe or others), By default, Wazuh might not have a specific rule for this, but you will see the event in the Wazuh event index (Sysmon Event ID 1 for the enumeration command). If desired, you could create a custom rule to flag commands like "net localgroup" usage. Otherwise, this can be observed manually in the log data.

   - Automated Exfiltration (T1020): Depending on how this atomic test works, it might use s script or utility to archive data and simulate sending it out. Check for any alerts related to data archive creation or network transfers. Wazuh’s default rules might not explicitly say "exfiltration," but you could see file creation events (Sysmon ID 11/12) or network connection events (Sysmon ID 3) in the logs. For instance, if the test used BITS or FTP, there might be an alert (e.g., Wazuh might alert on BITS jobs or unusual network connections). Ensure to inspect the Wazuh event logs for clues (e.g., search by the technique ID if our custom rule tagged it, or by process names involved).

   - Other Persistence Techniques (Scheduled Task, etc): If you ran any scheduled task test as an extra step, Wazuh's built-in rule 92154 should have logged "Task Scheduler activity detected". This show detection of persistence via scheduled task creation. Simularly, if any test tried modifying the registry of persistence or executed a know LOLBin (Living-off-the-Land binary) like regsvr32, Wazuh may log those (for example, rule 92226 for copying to startup folder, rule 92058 for application shimming, etc).


<img width="1640" height="717" alt="Captura de pantalla 2025-12-14 081544" src="https://github.com/user-attachments/assets/303d7149-2d69-4d10-8118-eadb4020d503" />
<img width="1917" height="1074" alt="Captura de pantalla 2025-12-15 025118" src="https://github.com/user-attachments/assets/e4f9010a-f04f-4c23-b11e-82b21c79ac21" />

After some time testing your dashboard may look like this:

<img width="1915" height="1075" alt="Captura de pantalla 2025-12-15 024349" src="https://github.com/user-attachments/assets/7b4b0770-b57a-4054-8ec4-e4d40e429760" />

 <img width="1917" height="1074" alt="Captura de pantalla 2025-12-15 025118" src="https://github.com/user-attachments/assets/3689fefb-488c-4be4-836a-9c6ef0b0ac5e" />
 Note: I tried executing T1059.001 and after some time I forgot to cleanup the temporary files and then I checked the dashboard and It was like that, LOL.

 <img width="1918" height="1077" alt="Captura de pantalla 2025-12-15 025201" src="https://github.com/user-attachments/assets/d3be2cdc-aa1c-4194-810b-b9bb9293cb36" />


In summary, after running the simulations, you should see multiple security alerts in Wazuh corresponding to the actions performed:
   - New user account creation (Initial Access/Persistence) – alerted by Windows Security event rules.
   - LSASS access attempt (Credential Access) – high-severity alert by Sysmon rule.
   - Scheduled task creation (Persistence) – if tested, alert for task scheduler.
   - File or network events for exfiltration – logged for analysis.

Each alert in Wazuh is mapped to MITRE tactics and techniques, either automatically by Wazuh or via custom rules, helping to identify the phase of the attack. For instance, the LSASS alert will be marked as Credential Access (T1003.001), the account creation as Persistence/Privilege Escalation (T1078 or T1136), etc. This mapping provides immediate context on what tactic the detected activity represents, which is valuable for analysts.

It’s a good practice to investigate each alert in the Wazuh dashboard: check the full log message, process names, user accounts involved, and other data. This lab not only shows that an alert fired, but also encourages understanding why it fired. For example, if an alert says a suspicious process accessed LSASS, one can correlate that with the atomic test that was run, confirming the detection capability.

# Conclusion and Next Steps
By completing this lab, we have configured a Wazuh-monitored Windows host with enhanced logging (Sysmon) and executed simulated attacks covering multiple MITRE ATT&CK tactics. The Wazuh platform was able to capture detailed events and generate alerts for these activities, demonstrating its effectiveness in threat detection. Importantly, this lab can be expanded: you can add more Atomic Red Team tests to cover additional techniques or integrate other tools (such as Caldera or Metasploit in a controlled manner) to further enrich the simulation.

For further exploration:
   - Review the Wazuh alert logs and the MITRE ATT&CK dashboard to see how Wazuh categorizes each event. This helps in understanding detection coverage.
   - Try tweaking or adding custom Wazuh rules for techniques that didn’t have obvious alerts (for example, command-line detection for reconnaissance commands).
   - Update the Sysmon configuration for more verbosity or specific detections (Sysmon has many settings; a more targeted config can capture additional behaviors).
   - Ensure to keep your lab isolated and revert snapshots as needed to clean up the changes made by atomic tests.

With this repository’s materials (documentation and sample rules), others can reproduce the detection lab and learn how endpoint telemetry combined with a SIEM like Wazuh can detect adversary behavior mapped to MITRE ATT&CK. Happy testing!

Author: Cristian Jimenez

# Repository Structure
```
Wazuh-Detection-Lab-MITRE-ATTACK-Adversary-Simulation/
├── README.md   # Proyecto de laboratorio (documentación en inglés)
├── Configuration/
│   └── Sysmonconfig.xml   # Reglas personalizadas de Sysmon
└──  LICENSE     # Licencia de código abierto (MIT) para el proyecto
```

# Some Resources:

   - Atomic Red Team GitHub Repository:
     https://github.com/redcanaryco/atomic-red-team

   - Official Atomic Red Team Website:
     https://atomicredteam.io

   - Rich and Well-Structured Documentation:
     https://github.com/redcanaryco/atomic-red-team/wiki

     - MITRE ATT&CK Framework:
       https://attack.mitre.org/
