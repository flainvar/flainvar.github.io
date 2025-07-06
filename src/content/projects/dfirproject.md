---
title: 'Setting up our own DFIR Homelab.'
description: A step by step guide to set up your own DFIR lab. 
publishDate: 'Jun 26 2025'
isFeatured: true
tags:
  - Network
  - Splunk
  - Active Directory
  - Windows
  - Ubuntu Server

---

## Construyendo Nuestro Homelab DFIR: Esquema de Red

As we begin our journey in building our own DFIR homelab, we need to design the network in order to properly set up the environment.

This project features an internal network composed of three virtual machines, as follows:

First, a Windows Server machine that acts as the Domain Controller. This virtual machine will also function as the router, so it will require two different network adapters.

The external adapter will be connected to our external network, while the internal adapter will connect to our internal network. We will assign a static IP address for the internal network and configure the necessary protocols to make the environment fully functional.

| Function          | Windows Server Role / Feature      | Primary Protocols/Services |
| :---------------- | :--------------------------------- | :------------------------- |
| Routing           | Remote Access (NAT, Routing)       | TCP/IP, NAT, RIP (optional) |
| Domain Controller | Active Directory Domain Services   | Kerberos, LDAP/LDAPS, DNS  |
| IP Assignment     | DHCP Server                        | DHCP                       |
| Name Resolution   | DNS Server                         | DNS                        |
| Time Sync         | (Built-in with AD DS)              | NTP                        |

Second, we have a Windows 10 virtual machine that will serve as the client.
Third, we will use an Ubuntu Server that will host our DFIR tools. We plan to use Splunk to ingest data from Windows security logs, and Zeek to monitor the network. Additionally, we will include an attacker machine running Parrot OS. The following diagram summarizes our setup:

![Diagrama de la red del homelab DFIR](/dfir1.png)

As the objective of this chapter is to build and configure the environment, we’ve created a simple playbook that we will continue to develop in future chapters. There, we’ll begin applying the tools installed on our Ubuntu server. Remember, it’s good practice to keep track of your machines’ IP addresses—make sure to document them!


### Initial Setup.

First, we will configure our LAN network adapter. We’ve chosen the following IP address for our server: 192.168.10.1/24. We also renamed the server to SRV-AD, and installed Active Directory Domain Services.

![Configuración inicial del servidor Windows y AD DS](/dfir2.png)

Once installed, we promoted the server to a Domain Controller (DC) and created a new forest: dfirproject.local.
Our next step was to set up DHCP. After this, we configured the routing options and were able to connect our Windows 10 client to the internal network.

![Conexión del cliente Windows 10 a la red interna](/dfir3.png)

All necessary configurations and installations for the Windows client have now been completed.
Let’s now move on to our Ubuntu server, where we will begin by installing Splunk. After installation, we need to initialize Splunk, which is located in /opt/splunk/bin, by running the following command:

./splunk start

After running the command, we configure our credentials and gain access to the web interface.

![Inicio de sesión en Splunk y panel de administrador](/dfir6.png)

and by introducing the credential mentioned before we can now access our administrator dashboard.

![Panel de administrador de Splunk](/dfir7.png)

It's important to configure the correct time zone preferences; skipping this step may cause issues when viewing logs. This can be done in the preferences section of the dashboard.

![Dashboard de administrador de Splunk](/dfir8.png)

Next, we will install the Splunk Add-on for Microsoft Windows. This add-on is essential for collecting and processing data from Windows environments within Splunk. It enables the collection of system performance metrics (CPU, disk, memory, I/O), log files, configuration data, user data, and more. To install it, click on Apps and search by name.

Now, we will configure data receiving by going to:

![Instalación de Splunk Add-on para Windows](/dfir9.png)

now we are gonna configure the data receiving by clicking on **settings > forwarding and receiving > configure receiving > new receiving port**. We enable port 9997, which is the default.

![Configuración del puerto de recepción de datos en Splunk](/dfir10.png)

Our next step is to install the Splunk Universal Forwarder on our Windows machines.

---

Once installed, navigate to:

SplunkUniversalForwarder/etc/system/local

Here, we create the inputs.conf file (you can copy it from the default directory). After creating it, we must run the Forwarder as administrator and modify the file to collect the logs we need. At the end of the file, we add the following:

[WinEventLog://Security]
disabled = false
start_from = oldest
current_only = false
checkpointInterval = 5
renderXml = true

[WinEventLog://System]
disabled = false

[WinEventLog://Application]
disabled = false

Now, we go to Services on the Windows host and change the SplunkForwarder service’s logon settings.

![Configuración del servicio SplunkForwarder en Windows](/dfir11.png)

Once everything is configured, if we perform a new search in Splunk, we should finally see data from our Windows machine.

![Registros de Windows visualizados en Splunk](/dfir12.png)

We will now repeat this process on our Windows Server machine.
---

#### Extra:

* I had to add a rule to allow traffic on port 9997 from the Windows machine.
* I should have assigned a static IP to the Ubuntu server. I missed this step during the initial setup but corrected it later.

---

### 1.2 Adding more inputs and tools to our homelab:

#### 1.2.1 Installing sysmon:

We will also install Sysmon on our Windows machines. You can download it from [here](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). To use it, you'll need a configuration XML file. We are using the SwiftOnSecurity configuration, which you can find [here](https://github.com/SwiftOnSecurity/sysmon-config).

After downloading and configuring Sysmon, return to the inputs.conf file on the Forwarder and add the following:

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false

**Remember to restart the SplunkForwader process to make it functional!**

---

Thank you so much for reading this far. This is the beginning of a journey I hope to enjoy alongside anyone who has the same passion for learning about cybersecurity as I do. Thanks to Andi for bringing me here. This is just the beginning! Later this week, you'll have a new post where we'll get started: we'll explore how to detect attacks and common practices in Windows using Splunk.

---
