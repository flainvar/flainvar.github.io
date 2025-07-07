---
title: 'Detección de ataques a Windows utilizando Splunk.'
description: Detección de reconocimientos y passwords sprayings y LLMNR/NBT-NS Poisoning.
publishDate: 'Jun 26 2025'
isFeatured: true
tags:
  - Network
  - Splunk
  - Active Directory
  - Windows
  - Ubuntu Server

---

De aquí en adelante, las entradas serán en español.  En tanto que estoy preparándome la CDSA de HackTheBox, el contenido se basará en el modulo con el mismo nombre (en inglés) de esta web: Detecting Windows Attacks with Splunk. En esta primera entrada estudiaremos como detectar reconocimientos, utilizando los nativos de windows y BloodHound/SharpHound, como detectar un Password Sprying y, por último,  LLMNR/NBT-NS Poisoning.

Además, situaremos estas tácticas en el marco de MITRE ATT%CK (Adversarial Tactics, Techniques, and Common Knowledge). El framework se vuelve crucial en cuanto se trata del diseño de defensas y detecciones.

## Detectando reconocimiento de usuarios y dominios comunes.

Una de las fases centrales del ciclo del hacking es el reconocimiento (recon). Los objetivos del reconocimiento son entender la arquitectura y la topología de red, las medidas de seguridad y las potenciales vulnerabilidades. Así, los atacantes se centrarán en identificar componentes cruciales de la red: Controladores de dominio, cuenta de usuarios y grupos, relaciones de confianza, unidades organizativas, políticas de grupos…

### Reconocimiento utilizando los ejecutables nativos de Windows.

Algunos de sus usos comunes son: 

whoami /all

Muestra el identificador de seguridad (SID) del usuario actual, sus membresías de grupo y sus privilegios. El modificador /all proporciona una salida muy detallada, incluyendo todos los SIDs a los que pertenece el usuario, los privilegios de seguridad que posee (ej. SeDebugPrivilege, SeImpersonatePrivilege) y cualquier SID restringido.

wmic computersystem get domain

Consulta la Instrumental de administración de Windows (WMI) para recuperar información sobre el sistema informático. Específicamente, obtiene el nombre del dominio al que está unido el equipo.

net user /domain

Lista todas las cuentas de usuario presentes en el dominio al que está unido el equipo actual. Consulta Active Directory para obtener esta información.

net group "Domain Admins" /domain

Lista todas las cuentas de usuario que son miembros del grupo "Administradores de dominio" dentro del dominio actual. Este comando consulta específicamente Active Directory.

arp -a

Muestra la caché del Protocolo de resolución de direcciones (ARP) en la máquina local. La caché ARP asigna direcciones IP a sus correspondientes direcciones MAC (Media Access Control).

nltest /domain_trusts

Prueba y muestra información sobre las relaciones de confianza entre dominios en un bosque de Active Directory. Las relaciones de confianza permiten a los usuarios de un dominio acceder a recursos en otro.

Para detectar estos métodos de reconocimientos con Splunk utilizaremos los registros de Sysmon. Estos eventos constan de un identificador, el identificador que nos interesa aquí es el 1: creación de proceso. Hemos recreado un whoami /all y podemos detectarlo con la siguiente búsqueda: 

![windet11](/windet11.png)

``` SPL
index="dfirad" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 
| search OriginalFileName IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (OriginalFileName IN (cmd.exe,powershell.exe) AND Image IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(OriginalFileName) as process by ParentImage, ParentProcessId, User
| where mvcount(process) >= 3
```

index="dfirad" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 

Esta primera parte es autoexplicativa, seleccionamos el index, la fuente y el ID de evento que nos interesa.

| search OriginalFileName IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (OriginalFileName IN (cmd.exe,powershell.exe) AND Image IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))

Esta parte es la que nos sirve para filtrar. Por un lado, filtramos aquellos procesos con nombre concreto que nos interesan y añadimos un AND para incluir la CMD y la powershell siempre y cuando se contengan las subcadenas que nos interesan. 

| stats values(OriginalFileName) as process by ParentImage, ParentProcessId, User

Aquí seleccionamos información adicional para que se nos muestre. 

| where mvcount(process) >= 3

Y, por último, estableces un filtro de "comportamiento" para evitar falsos positivos y centrar más nuestra búsqueda. 

Para finalizar, referenciamos lás técnincas aquí empleadas en el marco de MITRE y sus propuestas de mitigación:

T1087.002 – Account Discovery: Domain Account

> Prevent administrator accounts from being enumerated when an application is elevating through UAC (Contro de Cuentas de Usuario) since it can lead to the disclosure of account names. The Registry key is located at HKLM\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators. It can be disabled through GPO: Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: Enumerate administrator accounts on elevation.

T1018 – Remote System Discovery, T1069.002 – Permission Groups Discovery: Domain Groups and T1518.001 – Software Discovery: Security Software Discovery

>This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features. 

Esto quiere decir que tendremos que hacer hincapié en la detección de la ejecución de comandos, el acceso a ficheros y la creación de conexiones de red y los procesos, como hemos elaborado previamente. 



### Reconocimiento utilizando BloodHound/SharpHound.

Bloodhound es una herramienta de enumeración que permite el reconocimiento y la visualización de un dominio de active directory. El software funciona ejecutando consultas LDAP hacia el DC (Domain Controller). LDAP (Lightweight Directory Access Protocol) es un protocolo de aplicación estándar que se utiliza para acceder a servicios de directorio, que son bases de datos centralizadas que almacenan información sobre usuarios, grupos y otros recursos, es decir, es algo así como las páginas amarillas del active directory.

Es difícil de detectar con los eventos de Windows, por ello, microsoft lanzó una lista de consultas LDAP habitualmentes utilizadas en el reconocimiento con bloodhound, que es lo que utilizaremos para detectarlo: 

| Recon Tool                        | Filter                                                                 |
|-----------------------------------|-----------------------------------------------------------------------|
| enum_ad_user_comments (Metasploit) | (&(&(objectCategory=person)(objectClass=user))(\|(description=*pass*)(comment=*pass*))) |
| enum_ad_computers (Metasploit)     | (&(objectCategory=computer)(operatingSystem=*server*))                |
| enum_ad_groups (Metasploit)        | (&(objectClass=group))                                               |
| enum_ad_managedby_groups (Metasploit) | (&(objectClass=group)(managedBy=*)),<br>(&(objectClass=group)(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648)) |
| Get-NetComputer (PowerView)        | (&(sAMAccountType=805306369)(dnshostname=*))                         |
| Get-NetUser - Users (Powerview)    | (&(samAccountType=805306368)(samAccountName=*)                        |
| Get-NetUser - SPNs (Powerview)     | (&(samAccountType=805306368)(servicePrincipalName=*)                  |
| Get-DFSshareV2 (Powerview)         | (&(objectClass=msDFS-Linkv2))                                        |
| Get-NetOU (PowerView)              | (&(objectCategory=organizationalUnit)(name=*))                        |
| Get-DomainSearcher (Empire)        | (samAccountType=805306368)                                           |

Para ello, necesitaremos una nueva herramienta en nuestro cliente: SilkETW. Para ello vamos a generar una carpeta de logs y vincularla con el SplunkForwader, tal como hicimos en la entrada anterior con otras herramientas. 

Hemos decidido que, para esta muestra, no es necesario instalar el servicio de Silk. Para ello simplemente lanzaremos el ejecutable a la par que recreamos el ataque con Sharphound y, finalmente, ingestaremos los logs:

![windet12](/windet12.png)

Una vez generado, realizamos la siguiente búsqueda:

``` SPL
index="dfirad" source:"C:\\logs\\SilkETW\\ldap_events.json"
| spath input=Message
| rename XmlEventData.* as *
| search SearchFilter="*(samAccountType=805306368)*"
| stats values(SearchFilter) by ProcessID, ProcessName, DistinguishedName
```
![windet13](/windet13.png)

¡Bingo! Ahí tenemos nuestra entrada localizando el proceso. Vamos a desentrañar esta busqueda:

El filtrado de index y source que ya conocemos, localizando los logs. 
El comando spath se utiliza para extraer campos del campo "Message" que contiene datos estructurados en formato XML o JSON. Los identifica automáticamente.
El comando rename nos sirve para renombrar los elementos de XML que empiezan con XmlEventData. eliminando ese prefijo.
El comando search nos sirve para filtrar eventos que contengan la cadena que hemos seleccionado, en nuestro caso: (samAccountType=805306368) que, en las consultas de LDAP, se refiere a las cuentas de usuario. Es equivalente a: objectClass=user.
La mayoría de las consultas LDAP legítimas suelen ser específicas. Por el contrario, SharpHound genera consultas genéricas, como se muestra en la imagen posterior. Adeem Mawani (2021), en esta entrada de blog, señala, además, lo siguiente como característico: 
-Búsquedas genéricas para todos los objetos de un tipo general. 
-Gran número de filtros en una consulta única.
-Multiples consultas desde un PID único en un breve lapso de tiempo.
-Uso de comodines en el campo "SearchFilter".

![windet14](/windet14.png)

Veamos que subténicas podríamos destacar en esta sección. Además de las que hemos mencionado previamente: T1069.002 – Permission Groups Discovery: Domain Groups y T1087.002 – Account Discovery: Domain Account, podemos destacar: 

T1482 – Domain Trust Discovery

>M1047 - Audit: Map the trusts within existing domains/forests and keep trust relationships to a minimum.
>M1030 - Network Segmentation: Employ network segmentation for sensitive domains.

Cómo podemos ver, un buen bastionado y una correcta segmentación de red es vital para la seguridad defensiva y son dos carácteristicas necesarias para la postura de seguridad de cualquier empresa.


## Detectando Password Sprying.

El password sprying es un método que distribuye ataques a través de múltiples cuentas usando un conjunto limitado de contraseñas. Este método trata de evadir los bloqueos de cuentas que se suelen establecer en las políticas. Vamos a recrearlo:

![windet15](/windet15.png)

¿Cómo podemos detectar el password sprying?
El método más habitual es el Event ID 4625 - Failed logon, de los logs de seguridad de windows. También podemos detectarlo a través de otros eventos cómo:
4768 and ErrorCode 0x6 - Kerberos Invalid Users
4768 and ErrorCode 0x12 - Kerberos Disabled Users
4776 and ErrorCode 0xC000006A - NTLM Invalid Users
4776 and ErrorCode 0xC0000064 - NTLM Wrong Password
4648 - Authenticate Using Explicit Credentials
4771 - Kerberos Pre-Authentication Failed
Utilizaremos la siguiente búsqueda: 

``` SPL
index="dfirad" source="WinEventLog:Security" EventCode="4625"
| bin span=15m _time
| stats values(Nombre_de_cuenta) as Users by source, "Dirección de red de origen", dest, EventCode, Motivo_del_error
```

Vamos a explicar por qué:
el comando bin se usa para crear bloques de tiempo que son la clave aquí, dado el funcionamiento del password spray. Recordemos que este método prueba una misma contraseña para un grupo diferente de usuarios evitando el bloqueo. Así, un gran número de intentos en un periodo de tiempo determinado con diferentes usuarios es indicativo del password sprying.

![windet16](/windet16.png)

Está subtécnica está referenciada en el marco Mitre como: T1110.003 – Brute Force: Password Spraying y sus mitigaciones recomendadas son:

>M1036 - 	Account Use Policies: Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges. Consider blocking risky authentication requests, such as those originating from anonymizing services/proxies.

>M1032 - Multi-factor Authentication: Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.

>M1027 - Password Policies: Refer to NIST guidelines when creating password policies.

## Detectando Responder-like attacks

El LLMNR y NBT-NS poisoning, también conocidos por NBNS spoofing atacan ineficiencias del protocolo de resolución de nombres. Estos protocolos se utilizan para resolver hostnames a IPs cuando falla el FQDN. Funciona como se muestra a continuación (fuente: Hack the box): 

![windet17](/windet17.png)

El objetivo de este ataque es conseguir el NetNTML Hash con la intención de, o bien descifrarlo, o bien retransmitirlo para obtener acceso a sistemas. 
Hemos recreado el ataque configurando responder.py para que escuchara la red y conseguido el hash de la cuenta administrador. Vamos a ver como queda registrado en los logs. 

![windet18](/windet18.png)

Para cumplir con este objetivo utilizaremos el evento de sysmon con ID 22. Que podemos utilizar para encontrar archivos compartidos que no existen o están mal nombrados. 

``` SPL
index="dfirad" source:"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="22"
| table _time, Computer, user, Image, QueryName, QueryResults
```

![windet19](/windet19.png)

Y Aquí lo tenemos, podemos observar como se ha conectado a nuestra máquina atacante, cuya IP acaba en 103.

Esta subtenica está referenciada como: T1557.001 veamos sus mitigaciones: 

>M1042 - Disable or Remove Feature or Program: disable LLMNR and NetBIOS in local computer security settings or by group policy if they are not needed within an environment. 

>M1037 - Filter Network Traffic: use host-based security software to block LLMNR/NetBIOS traffic. Enabling SMB Signing can stop NTLMv2 relay attacks.

>M1031 - Network Intrusion Prevention: network intrusion detection and prevention systems that can identify traffic patterns indicative of AiTM activity can be used to mitigate activity at the network level.

>M1030 - Network Segmentation: network segmentation can be used to isolate infrastructure components that do not require broad network access. This may mitigate, or at least alleviate, the scope of AiTM activity.

## Useful splunk queries:

Recapitulamos con una recopilación de las busquedas concretas que hemos utilizado. Si estás atascado con las tareas del curso puede que te sirvan de ayuda. Pero, cuidado,puede que tus campos no tengan los mismos nombres que los míos:

### Detecting recons:

#### Windows' native:

``` SPL
index="dfirad" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 
| search OriginalFileName IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (OriginalFileName IN (cmd.exe,powershell.exe) AND Image IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(OriginalFileName) as process by ParentImage, ParentProcessId, User
| where mvcount(process) >= 3
```

#### Bloodhund/Sharphund

``` SPL
index="dfirad" source:"C:\\logs\\SilkETW\\ldap_events.json"
| spath input=Message
| rename XmlEventData.* as *
| search SearchFilter="*(samAccountType=805306368)*"
| stats values(SearchFilter) by ProcessID, ProcessName, DistinguishedName
```

### Detecting Password Spraying:

``` SPL
index="dfirad" source="WinEventLog:Security" EventCode="4625"
| bin span=15m _time
| stats values(Nombre_de_cuenta) as Users by source, "Dirección de red de origen", dest, EventCode, Motivo_del_error
```

### Detecting responder-like attack:

``` SPL
index="dfirad" source:"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="22"
| table _time, Computer, user, Image, QueryName, QueryResults
```