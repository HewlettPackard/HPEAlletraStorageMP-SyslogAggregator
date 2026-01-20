# HPE Alletra MP B10000 Syslog Aggregator
The syslog aggregator is an instance of FluentD configured to ingest security syslog messages from one or more HPE Alletra MP B10000 systems via TLS and transform the data into JSON formatted logs with key value pairs aligned with the Elastic Common Schema.

The FluentD configuration and a deployment script are provided.

# Legal Disclaimer
This script is open-source and is not supported under any Hewlett Packard Enterprise support program or service. The author and Hewlett Packard Enterprise further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.

In no event shall Hewlett Packard Enterprise, its authors or anyone else involved in the creation, production or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or the inability to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.

# Deployment script

The deployment script simplifies the deployment of the fluentd-based syslog aggregator and performs the following functions:

- Downloads and installs FluentD v6 LTS
- Creates the required directories
- Creates a root only environment file with a ransomly generated passphrase
- Writes the FluentD configuration file
- Generates a private RSA key with the previously creared passphrase
- Generates a certificate signing request based on user input
- Pauses for the user to paste in the PEM data from the signed certificate and the root CA
- Creates a symlink-helper tool to create a symlink between {Serial_number}.current.log and the current days log which runs daily at midnight

## Requirements

- Ubuntu 24.04 (Noble Numbat) system with appropriate memory and storage for the amount of logs to be ingested and processed (min 2 CPU, 8GB RAM, 160GB storage)
- Internet connectivity to download the content
- Appropriate proxy server information configured to allow curl to use a proxy without additional arguments (if appropriate)

# Deployment

Download hpe_alletra_mp_syslog_aggregator_deploy_v1.0.sh and enable execution 

sudo chmod +x ./hpe_alletra_mp_syslog_aggregator_deploy_v1.sh

Run as sudo

sudo ./hpe_alletra_mp_syslog_aggregator_deploy_v1.sh

## Certificate installation

During installation a 4096-bit RSA private key will be generated you will be prompted to enter the information required for the TLS certificate signing request. Once the CSR has been generated copy and paste the PEM text and submit to your CA.

Once the certificate has been signed, copy and paste the PEM data back into the deployment prompt:

[+] Generating strong random passphrase, writing EnvironmentFile

[+] Writing Fluentd configuration to /etc/fluent/fluentd.conf

[+] Generating AES-256–encrypted RSA private key (4096-bit)
....+............+...+...+....+...+..+.+.....+....+...+......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.....+.........+....+.........+...............+......+..+.......+.....+.+.....+.+.....+.........+....+..+.+........+......+.........+....+.....+...+....+.........+..+.......+...............+.....+.......+......+.....+...+....+............+.........+..+...+...................+......+............+............+...........+......+.+.....+....+.....+................+.................+...+.........+.............+...+........+.+...+............+......+...+.................+.........+.+...+..+..........+...+..............+...............+.+......+.....+.+.........+.....+...+......+.........+.............+.................+.......+.....+..........+......+.........+...+..+...................+.....+.+.....+.+.....+...+............+......................+............+...+........+...+.+......+........+.........+...+..........+.........+...+........+.......+......+..............+.+.....+....+...+...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
...+...+....+........+.......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+..+...............+....+.........+.....+.+...+...........+.+........+...+...+....+...+..+......+......+.+...+..+...+.......+..+.+...........+...+......+.+........+.+..+...+.+......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..........+..+.........+...+.+...............+......+.....+...+...............+.+.........+...+..+...+.........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

[+] Prompting for CSR DN fields and SANs (DNS/IP)
Country (C, 2-letter code) [e.g. GB]: GB
State/Province (ST) [e.g. England]: England
Locality/City (L) [e.g. Bristol]: Bristol
Organization (O) [e.g. Your Company Ltd]: Your Company Ltd
Organizational Unit(s) (OU, comma-separated): Your Org
Common Name (CN, FQDN): syslog.aggregator.xxx.yyy.zzz.net
Email Address (optional):
Subject Alternative Names (DNS, comma-separated): syslog.aggregator
Subject Alternative Names (IP, comma-separated): 11.22.33.44

[+] Creating CSR (PEM) at /etc/fluentd/certs/server.csr

[+] CSR preview (Subject & SANs)
        Subject: C = GB, ST = England, L = Bristol, O = Your Company Ltd, OU = Your Org, CN = syslog.aggregator.xxx.yyy.net
                X509v3 Subject Alternative Name:
                    DNS:syslog.aggregator, IP Address:11.22.33.44
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        7b:a8:24:9f:5c:08:4e:dc:09:86:b8:e6:4b:49:e6:95:c7:a4:
        2f:9d:97:98:dd:70:43:5e:56:c6:22:f3:4e:c2:23:f1:1c:14:
-----BEGIN CERTIFICATE REQUEST-----
MIIE+TCCAuECAQAwaDELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxEDAO
BgNVBAcMB0JyaXN0b2wxDDAKBgNVBAoMA0hQRTEMMAoGA1UECwwDVE1FMRkwFwYD
VQQDDBB0bWUtc2VjLXZhdWx0LTAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAu6ywT8J+yUgbURgimeW9+FImfgQhElyP0Mw98SgXT06sLAN44iH0dvjN
HdPFQMhHI1yaMqxU49nX2dKAtuNtfhd8OCHtD/fSNE1ukKocxKCEXVweixdGs3qB
...
qe7tmvCpfmuPevWkI5THgZdG1CC9uVK0Dy98Qyb60M2m7quP2X0Q4/2ziTGmP4bl
lZSKCJaHXSmauGXYdfdWHvxnuA/EFxjHbgWIuzUj1dkGlWzARM0+9jdI71JQy4QG
cJHGMgPjg1nLQuJhX+SC2SFVOCPrNsx3IacR7IBOW/tp/ZRQAV1V8Fm0bKo2e/wo
rAlsWeS4eOprrkjPJOr5TR4GAGFIF6lQF0L/H4EJUEKSGKSTCuSA21hp0tsMVRm8
D6h6P8PI79gM6MF9GwdAjAJaCi3b4l7mIvBUCidr00W8ZELQfRLrccjo69mkY93+
+waV7SiWbzCPUck2aYryV0khc3AfDk2ZggFZaTcW6h4zCCnOLBuG0U2sgqWd9/oF
nGRAd7q68/DjawcBOHM8CMPReMInSrQLQ77OFwFVXXV3LJV1KRydMBN+aJMpVDUU
KDev436hDausfXyJIgdP/eqLXEgJ7gCTCYyATdFGZX4GNtn/VgP9ZMZ4lQMniqb1
4OMUWGquzKHQJ+AvuZaq4TELX1rGRKoBYE8nP84=
-----END CERTIFICATE REQUEST-----
\nSubmit the CSR to your CA now. Press Enter to continue when ready to paste certificates.


[+] Paste the issued server certificate (PEM). End with CTRL-D.
-----BEGIN CERTIFICATE-----
MIIEqTCCA5GgAwIBAgIQK3Gbbf8r46eH3B4OTpBjVzANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApidWstdG1lLWNhMB4XDTI2MDEyMDEwMzkyNloXDTI4MDQyNDEw
MzkyNlowaDELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxEDAOBgNVBAcM
B0JyaXN0b2wxDDAKBgNVBAoMA0hQRTEMMAoGA1UECwwDVE1FMRkwFwYDVQQDDBB0
bWUtc2VjLXZhdWx0LTAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
u6ywT8J+yUgbURgimeW9+FImfgQhElyP0Mw98SgXT06sLAN44iH0dvjNHdPFQMhH
...
HRMEAjAAMB0GA1UdDgQWBBS7p19YatDR8N1kUR2NnT1Z1EkkxzBQBgNVHSMESTBH
gBRxwS3Yy2hPA6qH/j4GD0XWU3cwIKEZpBcwFTETMBEGA1UEAwwKYnVrLXRtZS1j
YYIUAqkIRJjyr0pAIg4+Gc+SXd6/DNAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwCwYD
VR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IBAQBPc6vX3bUWLuDkH1k5ZJJ18f4w
CdY6RZJjynWCch9YsVacFyJGqVIs1wFVI98airSHo9oOjlAH2YBC51lpxPZ5Z97p
k5X+ODtPTTkWFVMfSenp/KxYlhni33VHy3hBYU1OoUXPhYawRndH5tFF06cqTl0a
WC2c/Gu1llzhO49p8gQA3AUaYctiDBgGv5WHCyAVy0wkO4SWvD2FTRAMBmIHiUZs
4Uicn/JGysqm9/Afaw3M50b6oH0PX+Iep6/5xNeWQl5bIoP79EJgQv/96hFlbucU
3vaR5b2HzpUYjefsdSiChmgbX6DS0bS67lx2zjAAOi99FyDblops9xhrdlkR
-----END CERTIFICATE-----

[+] Paste the CA certificate (PEM). End with CTRL-D.
-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIUAqkIRJjyr0pAIg4+Gc+SXd6/DNAwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKYnVrLXRtZS1jYTAeFw0yNTA3MTAxMDE4MTNaFw0zNTA3
MDgxMDE4MTNaMBUxEzARBgNVBAMMCmJ1ay10bWUtY2EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDSv9O8FCO1cIQsfoXmADm+lQxuz5nOozQcb7IYncAb
QIpmBwYVsuKk7tIp3tXdOLmvTj3MvFaskyjiefdsiaZzrjbcqqhV4XKW7P6jAT+4
...
ZdomypJ2sRP9aOhr7vIIQa9wBE6lqoysFqG/d77lL7DYeAmhMJkYV2myFRgLLIxt
Rf+tfA2bOMaWHfvawbMsyuj+hmTAMe3MKDN3Lw7qQ2Aky344OT/cKL+AxkGQhroR
VLS3McBYqHzHrjtPPXIRJevCet5z1Lz4IDhMUQ==
-----END CERTIFICATE-----

## Post installation

The script may finish with the line:

[!] No 6514 listener found yet.

Once the deployment has finished verify that FluentD is listening on TCP 6514 using sudo netstat -tulpn | grep 6514
