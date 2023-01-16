#!/bin/bash

ip=$1

# Perform fast nmap scan
nmap -Pn -T4 -sV -p- $ip -oN "nmap_scan.txt"

# Parse nmap output to find open ports
open_ports=$(grep -Eo "([0-9]{1,5})/open" nmap_scan.txt | cut -d'/' -f1)

# Loop through open ports to perform enumeration
for port in $open_ports
do
    case "$port" in
        21)
            # FTP (21/tcp)
            echo "Running nmap scan on FTP (21/tcp)..."
            nmap_ftp_cmd="nmap -Pn -sV -p 21 --script='banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)'"
            echo $nmap_ftp_cmd
            $nmap_ftp_cmd -oN "tcp_21_ftp_nmap.txt" $ip
            ;;
        22)
            # SSH enumeration
            echo "Running nmap scan on SSH (22/tcp)..."
            nmap_ssh_cmd="nmap -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods"
            echo $nmap_ssh_cmd
            $nmap_ssh_cmd -oN tcp_22_ssh_nmap.txt $ip
            ;;
        25)
            # SMTP enumeration
            echo "Running nmap scan on SMTP (25/tcp)..."
            nmap_smtp_cmd="nmap -Pn -sV -p 25 --script='banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)'"
            echo $nmap_smtp_cmd
            $nmap_smtp_cmd -oN tcp_25_smtp_nmap.txt $ip

            echo "Running smtp-user-enum on SMTP (25/tcp)..."
            smtp_user_enum_cmd="/home/kali/.local/bin/smtp-user-enum -V -m RCPT -w -f '<user@example.com>' -d 'domain.local' -U '/usr/share/metasploit-framework/data/wordlists/unix_users.txt'"
            echo $smtp_user_enum_cmd
            $smtp_user_enum_cmd $ip 25 2>&1 | tee "tcp_25_smtp_user-enum.txt"
            ;;
        53)
           # DNS (53/tcp, 53/udp)
            echo "Running nmap scan on DNS (53/tcp, 53/udp)..."
            nmap_dns_cmd="sudo nmap -Pn -sU -sV -p 53 --script='banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)'"
            echo $nmap_dns_cmd
            $nmap_dns_cmd -oN udp_53_dns_nmap.txt $ip

            echo "Performing zone transfer (tcp/53) on DNS..."
            dig_cmd="dig axfr @$ip $domain"
            echo $dig_cmd
            $dig_cmd 2>&1 | tee "tcp_53_dns_dig.txt"

            echo "Performing reverse DNS lookup (may display NS record containing domain name)..."
            nslookup_cmd="nslookup $ip $ip"
            echo $nslookup_cmd
            $nslookup_cmd

            echo "Brute forcing subdomains on DNS..."
            gobuster_dns_cmd="gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 16"
            echo $gobuster_dns_cmd
            $gobuster_dns_cmd -o "tcp_53_dns_gobuster.txt"
            ;;
        80|443)
            # HTTP/HTTPS (80/tcp, 443/tcp)
            echo "Running nmap scan on HTTP/HTTPS (80/tcp, 443/tcp)..."
            nmap_http_cmd="nmap -Pn -sV -p $port --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)'"
            echo $nmap_http_cmd
            $nmap_http_cmd -oN tcp_port_protocol_nmap.txt $ip 

            echo "Running ffuf on HTTP/HTTPS (80/tcp, 443/tcp)"
            ffuf_cmd="ffuf -w /usr/share/wordlists/dirb/common.txt -u https://$ip/FUZZ"
            echo $ffuf_cmd
            $ffuf_cmd 2>&1 | tee "fuff.txt"

            echo "Running Nikto scan on HTTP/HTTPS (80/tcp, 443/tcp)..."
            nikto_cmd="nikto -h http://$ip"
            echo $nikto_cmd
            $nikto_cmd 2>&1 | tee "tcp_port_protocol_nikto.txt"

            echo "Running directory brute force on HTTP/HTTPS (80/tcp, 443/tcp)..."
            gobuster_http_cmd="gobuster dir -u http:// $ip -w /usr/share/seclists/Discovery/Web-Content/common.txt -x 'txt,html,php,asp,aspx,jsp' -s '200,204,301,302,307,403,500' -k -t 16"
            echo $gobuster_http_cmd
            $gobuster_http_cmd -o "tcp_port_protocol_gobuster.txt"

            echo "Running dirsearch on HTTP/HTTPS (80/tcp, 443/tcp)..."
            dirsearch_cmd="python3 /opt/dirsearch/dirsearch.py -u $url -t 16 -e txt,html,php,asp,aspx,jsp -f -x 403 -w /usr/share/seclists/Discovery/"
            echo $dirsearch_cmd 
            $dirsearch_cmd
            ;;
        88) 
            # Kerberos (88/tcp, 464/tcp)
            echo "Kerberos Version detection + NSE scripts"
            $kerb_cmd="nmap -Pn -sV -p $port --script="banner,krb5-enum-users" -oN "tcp_port_kerberos_nmap.txt" $ip"
            echo $kerb_cmd
            $kerb_cmd
            ;;
        110|995)
            # POP3/POP3S (110/tcp, 995/tcp)
            echo "POP Version detection + NSE scripts"
            pop_cmd = "nmap -Pn -sV -p $port "--script=banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN tcp_port_pop3_nmap.txt $ip"
            echo $pop_cmd
            $pop_cmd
            ;;
        111|135)
            # RPC (111/tcp, 135/tcp)
            echo "RPC Version detection + NSE scripts"
            rpc_version_cmd="nmap -Pn -sV -p $port --script=banner,msrpc-enum,rpc-grind,rpcinfo -oN tcp_port_rpc_nmap.txt $ip"
            echo $rpc_version_cmd
            $rpc_version_cmd

            echo "List all registered RPC programs (compact version"
            rpc_programs_cmd ="rpcinfo -s $ip"
            echo "rpc_programs_cmd"
            $rpc_programs_cmd

            echo "Trying to get a null session with rpc"
            rpc_null_cmd="rpcclient -U "" -N $ip"
            echo $rpc_null_cmd
            $rpc_null_cmd
            ;;
        113)
            # ident (113/tcp)
            echo "Enumerating users services running as on ident (113/tcp)..."
            ident_user_enum_cmd="ident-user-enum $ip 22 25 80 445"
            echo $ident_user_enum_cmd
            $ident_user_enum_cmd
            ;;
        123)
            # NTP (123/udp)
            echo "Running nmap NSE script for NTP (123/udp)..."
            nmap_ntp_cmd="sudo nmap -sU -p 123 --script ntp-info"
            echo $nmap_ntp_cmd
            $nmap_ntp_cmd $ip
            ;;
        137)
            # NetBIOS-NS (137/udp)
            echo "Running enum4linux for NetBIOS-NS (137/udp)..."
            enum4linux_cmd="enum4linux -a -M -l -d"
            echo $enum4linux_cmd
            $enum4linux_cmd $ip 2>&1 | tee "enum4linux.txt"
            
            echo "Running nbtscan for NetBIOS-NS (137/udp)..."
            nbtscan_cmd="nbtscan -rvh"
            echo $nbtscan_cmd
            $nbtscan_cmd $ip 2>&1 | tee "nbtscan.txt"
            ;;
        139|445)
            # SMB (139/tcp, 445/tcp)
            echo "Running nmap scan on SMB (139/tcp, 445/tcp)..."
            nmap_smb_cmd="nmap -Pn -sV -p 445 --script='banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)'"
            echo $nmap_smb_cmd
            $nmap_smb_cmd --script-args=unsafe=1 -oN tcp_445_smb_nmap.txt $ip

            echo "Running smbmap for SMB (139/tcp, 445/tcp)..."
            echo "Listing share permissions on SMB (139/tcp, 445/tcp)..."
            smbmap_cmd="smbmap -H $ip -P 445"
            echo $smbmap_cmd

            $smbmap_cmd 2>&1 | tee -a "smbmap-share-permissions.txt"
            smbmap_cmd_null="smbmap -u null -p \"\" -H $ip -P 445"
            echo $smbmap_cmd_null
            $smbmap_cmd_null 2>&1 | tee -a "smbmap-share-permissions.txt"

            echo "Listing share contents on SMB (139/tcp, 445/tcp)..."
            smbmap_cmd_R="smbmap -H $ip -P 445 -R"
            echo $smbmap_cmd_R
            $smbmap_cmd_R 2>&1 | tee -a "smbmap-list-contents.txt"
            smbmap_cmd_null_R="smbmap -u null -p \"\" -H $ip -P 445 -R"
            echo $smbmap_cmd_null_R
            $smbmap_cmd_null_R 2>&1 | tee -a "smbmap-list-contents.txt"

            echo "Running enum4linux for SMB (139/tcp, 445/tcp)..."
            enum4linux_cmd="enum4linux -a -M -l -d"
            echo $enum4linux_cmd
            $enum4linux_cmd $ip 2>&1 | tee "enum4linux.txt"

            echo "Running smbver.sh for SMB (139/tcp, 445/tcp)..."
            smbver_cmd="./smbver.sh $ip 139"
            echo $smbver_cmd
            sudo $smbver_cmd

            echo "Running null session for SMB (139/tcp, 445/tcp)..."
            echo $smbmap_cmd_null_session
            $smbmap_cmd_null_session

            smbclient_cmd_null_session="smbclient -L //$ip/ -U '' -N"
            echo $smbclient_cmd_null_session
            $smbclient_cmd_null_session

            echo "Enumerating shares on SMB (139/tcp, 445/tcp)..."
            nmap_cmd_enum_shares="nmap --script smb-enum-shares -p 445"
            echo $nmap_cmd_enum_shares
            $nmap_cmd_enum_shares $ip

            echo "Connecting to wwwroot share on SMB (139/tcp, 445/tcp)..."
            smbclient_cmd_wwwroot="smbclient \\\\$ip\\wwwroot"
            echo $smbclient_cmd_wwwroot
            $smbclient_cmd_wwwroot

            echo "Running Nmap scans for SMB vulnerabilities (NB: can cause DoS)..."
            nmap_cmd_ms06_025="nmap -Pn -sV -p 445 --script='smb-vuln-ms06-025' --script-args='unsafe=1' -oN 'tcp_445_smb_ms06-025.txt'"
            echo $nmap_cmd_ms06_025
            $nmap_cmd_ms06_025 $ip

            nmap_cmd_ms07_029="nmap -Pn -sV -p 445 --script='smb-vuln-ms07-029' --script-args='unsafe=1' -oN 'tcp_445_smb_ms07-029.txt'"
            echo $nmap_cmd_ms07_029
            $nmap_cmd_ms07_029 $ip

            nmap_cmd_ms08_067="nmap -Pn -sV -p 445 --script='smb-vuln-ms08-067' --script-args='unsafe=1' -oN 'tcp_445_smb_ms08-067.txt'"
            echo $nmap_cmd_ms08_067
            $nmap_cmd_ms08_067 $ip

            nmap_cmd_ms17_010="nmap -p 445 --script smb-vuln-ms17-010 -oN 'tcp_445_smb_ms17-010.txt'"
            echo $nmap_cmd_ms17_010
            $nmap_cmd_ms17_010 $ip
            ;;
        161)
            # SNMP (161/udp)
            echo "Running snmp-info NSE script for SNMP ( 161/udp)..."
            nmap_snmp_cmd="sudo nmap -sU -p 161 --script snmp-info $ip"
            echo $nmap_snmp_cmd
            $nmap_snmp_cmd

            echo "Running brute force community strings for SNMP (161/udp)..."
            onesixtyone_cmd="onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $ip"
            echo $onesixtyone_cmd
            $onesixtyone_cmd 2>&1 | tee "udp_161_snmp_onesixtyone.txt"   

            echo "Running snmpwalk for SNMP ( 161/udp)..."
            snmpwalk_cmd_1="snmpwalk -c public -v1 -t 10 $ip"
            echo $snmpwalk_cmd_1
            $snmpwalk_cmd_1
            snmpwalk_cmd_2="snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25"

            echo $snmpwalk_cmd_2
            $snmpwalk_cmd_2
            snmpwalk_cmd_3="snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2"

            echo $snmpwalk_cmd_3
            $snmpwalk_cmd_3
            snmpwalk_cmd_4="snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3"
            ;;
        389|3268)
            #LDAP
            echo "Running NSE scripts for LDAP (389/tcp, 3268/tcp)..."
            nmap_ldap_cmd="nmap -Pn -sV -p 389,3268 --script=\"banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"tcp_389_3268_ldap_nmap.txt\" $ip"
            echo $nmap_ldap_cmd
            $nmap_ldap_cmd 

            echo "Running enum4linux for LDAP (389/tcp, 3268/tcp)..."
            enum4linux_cmd="enum4linux -a -M -l -d $ip"
            echo $enum4linux
            ;;
        1100)
            #JAVA RMI
            echo "Running NSE scripts for Java RMI (1100/tcp)..."
            nmap_rmi_cmd="nmap -Pn -sV -p 1100 --script=\"banner,rmi-vuln-classloader,rmi-dumpregistry\" -oN \"tcp_1100_rmi_nmap.txt\" $ip"
            echo $nmap_rmi_cmd
            $nmap_rmi_cmd
            echo "Running NSE scripts for MSSQL (1433/tcp)..."
            ;;
        1433)
            #MSSQL
            echo "Running NSE scripts for MSSQL (1433/tcp)..."
            nmap_mssql_cmd="nmap -Pn -sV -p 1433 --script=\"banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=\"mssql.instance-port=1433,mssql.username=sa,mssql.password=sa\" -oN \"tcp_1433_mssql_nmap.txt\" $ip"
            echo $nmap_mssql_cmd
            $nmap_mssql_cmd
            echo "Running mssqlclient.py for MSSQL (1433/tcp)..."
            echo "List share permissions"
            mssqlclient_share_permissions_cmd="mssqlclient.py -db msdb hostname/sa:password@$ip"
            echo $mssqlclient_share_permissions_cmd
            $mssqlclient_share_permissions_cmd
            echo "List share contents"
    esac
echo "Enumeration complete"

                






        


        


        

