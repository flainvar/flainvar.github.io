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

As we begin our journey building our own DFIR homelab we need to scheme our network in order to set up the environment.

This project has an internal network composed of 3 virtual machines which are the followings:

First, a **windows servers** that acts as the **Domain Controller**. This virtual machine will behave, as well, as router itself so we will need two different network adapters.

The external adapter will be connected to our external network and the internal adapter will be connected to our internal network. We will need to set an static IP address for the internal network and configure protocols in order to make our project functional:

| Function          | Windows Server Role / Feature      | Primary Protocols/Services |
| :---------------- | :--------------------------------- | :------------------------- |
| Routing           | Remote Access (NAT, Routing)       | TCP/IP, NAT, RIP (optional) |
| Domain Controller | Active Directory Domain Services   | Kerberos, LDAP/LDAPS, DNS  |
| IP Assignment     | DHCP Server                        | DHCP                       |
| Name Resolution   | DNS Server                         | DNS                        |
| Time Sync         | (Built-in with AD DS)              | NTP                        |

Second, for the client, we will use a single **windows 10 VM**. And Third, an **ubuntu server** that will be used to host our DFIR tools: we are gonna use **Splunk** to ingest data from our windows security logs and **Zeek** to monitorize the network. We will need, as well, an attacker machine which OS will be **Parrot**. The diagram that follows summarize our plan:

![Diagrama de la red del homelab DFIR](/dfir1.png)

As our objective in this chapter is to set up this environment we set a very simple playbook that we may develop in the following chapters where we will put on practice the tools that we are installing in our ubuntu server. Remember that is a good practice to keep your PCs IPs tracked, note them!

---

### Installing and managing our Windows 2019 server.

First of all, we are gonna set up ours LAN network adapter, we have chose the following IP for our server: **192.168.10.1\24**. We have also change the name to **SRV-AD** and then we have installed Active Directory Domain Services:

![Configuración inicial del servidor Windows y AD DS](/dfir2.png)

once installed, we have promoted the server to DC and we have created a new forest: “**dfirproject.local**”. Our next step is to set up **DHCP**. After this, we configure the routing options and we can finally connect with our windows 10 client to our internal network:

![Conexión del cliente Windows 10 a la red interna](/dfir3.png)

All we needed to configure and install on windows is already done. Lets now dive into our ubuntu server where we have to, first of all, install splunk. After the installation we have to initialize splunk, located on /opt/splunk/bin and run:

./splunk start

After this, we configure some credentials and now we have access to our web server:

![Inicio de sesión en Splunk y panel de administrador](/dfir6.png)

and by introducing the credential mentioned before we can now access our administrator dashboard.

![Panel de administrador de Splunk](/dfir7.png)

it is important to set up the correct time zone preferences, if we Skip this step we may have problem visualizing our logs. We can do this on the preferences section.

![Dashboard de administrador de Splunk](/dfir8.png)

and we are gonna install **splunk add-on for microsoft windows**. The Splunk Add-on for Microsoft Windows is essential for collecting and processing data from Windows environments within Splunk. It enables the gathering of various data points, including system performance metrics (CPU, disk, memory, I/O), log files, configuration data, user data, and more. For this, we are gonna clic on apps and search by it’s name:

![Instalación de Splunk Add-on para Windows](/dfir9.png)

now we are gonna configure the data receiving by clicking on **settings > forwarding and receiving > configure receiving > new receiving port**. We are now allowing the port **9997** which is the default one.

![Configuración del puerto de recepción de datos en Splunk](/dfir10.png)

Our next step is to install the forwarder in our windows machines.

---

once installed, we will head to SplunkUniversalForwader/etc/system/local to create our input.conf archive (we can copy it from our default directory). Once we have created it, we are gonna run it as administrator and modified it for getting the logs that we want. So, we are adding at the end of the text the following:

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

Now we proceed to services on the windows hosts machines to changue “SplunkForwader” services loggin options.

![Configuración del servicio SplunkForwarder en Windows](/dfir11.png)

now, if we run a new search with splunk we will finally see the data from our windows machine:

![Registros de Windows visualizados en Splunk](/dfir12.png)

so we are gonna just do the same on our windows server machine.

---

#### Extra:

* I had to add rules on port 9997 from the windows machine to allow traffic.
* I should have assigned manual IP to ubuntu server. I didnt during the elaboration process of this article but I fixed it as soon as I noticed.

---

### 1.2 Adding more inputs and tools to our homelab:

#### 1.2.1 Installing sysmon:

We are gonna also install **sysmon** on our windows machines. We can download it from [here](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) and all we need is a config xml archive. We are using the SwiftOnSecurity xml archive and u can find it [here](https://github.com/SwiftOnSecurity/sysmon-config).

Now, we go back to our input file on the forwarder and we add the following:

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false

**Remember to restart the SplunkForwader process to make it functional!**

---

Thank you so much for reading this far. This is the beginning of a journey I hope to enjoy alongside anyone who has the same passion for learning about cybersecurity as I do. Thanks to Andi for bringing me here. This is just the beginning! Later this week, you'll have a new post where we'll get started: we'll explore how to detect attacks and common practices in Windows using Splunk.

---
