## Setting Up a Simulated Network Environment with Snort IDS on Ubuntu

### Introduction

This report outlines the steps to set up a simulated network environment, deploy Snort IDS sensors, configure detection rules, analyze network traffic, and respond to security incidents using Ubuntu. Snort is a powerful, open-source network intrusion detection system (NIDS) that performs real-time traffic analysis and packet logging on IP networks.

### Prerequisites

- A server running Ubuntu (20.04 or later)
- Non-root user with sudo privileges
- Basic knowledge of network security concepts
- Access to a terminal and command line interface

### Step 1: Setting Up the Simulated Network Environment

1. **Install VirtualBox and Ubuntu Server:**
   - Download and install VirtualBox from the official website.
   - Download the Ubuntu Server ISO file.
   - Create a new virtual machine in VirtualBox and install Ubuntu Server following the on-screen instructions.

2. **Configure Network Adapters:**
   - In VirtualBox, go to the settings of your virtual machine.
   - Under the "Network" tab, configure Adapter 1 to "NAT" and Adapter 2 to "Host-only Adapter."
   - Enable promiscuous mode for both adapters to allow Snort to capture all network traffic.

### Step 2: Installing Snort on Ubuntu

1. **Update the System:**
   ```bash
   sudo apt-get update
   sudo apt-get upgrade -y
   ```

2. **Install Required Dependencies:**
   ```bash
   sudo apt-get install -y gcc libpcre3-dev zlib1g-dev libluajit-5.1-dev libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet autoconf libtool
   ```

3. **Download and Install DAQ:**
   ```bash
   wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
   tar -zxvf daq-2.0.6.tar.gz
   cd daq-2.0.6
   ./configure && make && sudo make install
   ```

4. **Download and Install Snort:**
   ```bash
   wget https://www.snort.org/downloads/snort/snort-2.9.15.1.tar.gz
   tar -zxvf snort-2.9.15.1.tar.gz
   cd snort-2.9.15.1
   ./configure && make && sudo make install
   ```

### Step 3: Configuring Snort

1. **Set Up Configuration Files:**
   ```bash
   sudo mkdir /etc/snort
   sudo mkdir /etc/snort/rules
   sudo mkdir /etc/snort/preproc_rules
   sudo mkdir /var/log/snort
   sudo touch /etc/snort/rules/local.rules
   sudo touch /etc/snort/snort.conf
   ```

2. **Edit the Snort Configuration File:**
   ```bash
   sudo nano /etc/snort/snort.conf
   ```
   Add the following lines to configure Snort:
   ```plaintext
   ipvar HOME_NET 192.168.1.0/24
   ipvar EXTERNAL_NET !$HOME_NET
   include $RULE_PATH/local.rules
   output alert_fast: stdout
   ```

3. **Create a Basic Rule:**
   ```bash
   sudo nano /etc/snort/rules/local.rules
   ```
   Add the following rule to detect ICMP traffic:
   ```plaintext
   alert icmp any any -> $HOME_NET any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
   ```

### Step 4: Running Snort

1. **Test the Configuration:**
   ```bash
   sudo snort -T -c /etc/snort/snort.conf
   ```

2. **Run Snort in Detection Mode:**
   ```bash
   sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
   ```

### Step 5: Analyzing Network Traffic

1. **Generate Network Traffic:**
   - Use tools like `ping` or `nmap` to generate network traffic.
   - Example: `ping -c 4 192.168.1.1`

2. **Monitor Alerts:**
   - Snort will display alerts in the console for any traffic that matches the configured rules.

### Step 6: Responding to Security Incidents

1. **Review Alerts:**
   - Check the Snort logs located in `/var/log/snort` for detailed information about detected incidents.

2. **Incident Response Strategies:**
   - **Containment:** Isolate affected systems to prevent further damage.
   - **Eradication:** Remove the cause of the incident, such as malware or unauthorized access.
   - **Recovery:** Restore systems to normal operation and verify that the threat has been eliminated.
   - **Documentation:** Document the incident, response actions, and lessons learned for future reference.

### Findings and Analysis

- **Network Analysis Results:**
  - Detected ICMP traffic as per the configured rule.
  - Generated alerts were logged and displayed in the console.

- **Rule Configurations:**
  - Basic ICMP detection rule was effective in identifying ping requests.
  - Custom rules can be created to detect specific types of traffic or attacks.

- **Incident Response:**
  - Prompt detection and alerting allowed for quick response to potential threats.
  - Effective use of Snort's logging and alerting capabilities facilitated thorough analysis and documentation of incidents.

### Conclusion

Setting up a simulated network environment with Snort IDS on Ubuntu provides a robust platform for monitoring and analyzing network traffic. By configuring detection rules and responding to security incidents, network administrators can enhance their network security posture and mitigate potential threats effectively.

### Images and Screenshots

#### Snort Configuration File
Snort Configuration

#### Running Snort in Detection Mode
Running Snort

#### Snort Alert Example
Snort Alert

By following this guide, you can set up and configure Snort IDS on Ubuntu, enabling you to monitor your network for potential security threats and respond effectively to incidents.

Citations:
[1] https://www.youtube.com/watch?v=HEGoCWmHr8Y
[2] https://upcloud.com/resources/tutorials/install-snort-ubuntu
[3] https://www.youtube.com/watch?v=cD-DoKLzq2s
[4] https://hackertarget.com/snort-tutorial-practical-examples/
[5] https://www.researchgate.net/publication/358919795_Using_SNORT_Network_Intrusion_Detection_for_Real-Time_Packet_Inspection
[6] https://www.rapid7.com/blog/post/2017/01/11/how-to-install-snort-nids-on-ubuntu-linux/
[7] https://shape.host/resources/how-to-install-and-configure-snort-3-intrusion-detection-system-on-ubuntu-22-04
[8] https://github.com/OSTEsayed/CodeAlpha_Network_Intrusion_Detection_System
[9] https://reintech.io/blog/configure-snort-network-intrusion-detection-ubuntu
[10] https://www.youtube.com/watch?v=NcNQZm-q29M
[11] https://www.howtoforge.com/install-and-configure-snort-3-on-ubuntu-22-04/
[12] https://manpages.ubuntu.com/manpages/jammy/man8/snort.8.html
[13] https://www.linkedin.com/pulse/ns329-allinone-network-simulator-step-installation-guide-fekri-saleh
[14] https://cytoolz.com/blog/snort-3-install-and-configure-intrusion-detection-system-on-ubuntu-22-04
[15] https://arxiv.org/pdf/2308.13589.pdf
[16] https://superuser.com/questions/328201/how-to-configure-network-on-vm-ubuntu-server-with-host-changing-networks
[17] https://www.youtube.com/watch?v=nwDVE_kEFGg
[18] https://linuxier.com/how-to-install-snort-on-ubuntu/
[19] https://serverfault.com/questions/665440/set-up-network-interfaces-in-ubuntu-for-kvm-virtual-machine
[20] https://zhauniarovich.com/post/2020/2020-01-configuring-network/
