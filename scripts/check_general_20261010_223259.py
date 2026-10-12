import socket
import ssl
import http.client
import urllib.request
import subprocess

# ...

### 2. FTP Check
def check_ftp():
    try:
        ftp = ftplib.FTP('192.168.64.7')
        ftp.login()
        print("FTP service is running and accessible.")
        ftp.quit()
    except:
        print("FTP service is not running or not accessible.")

# ...

### 3. SSH Check
def check_ssh():
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('192.168.64.7', username='root', password='password')
        print("SSH service is running and accessible.")
        ssh.close()
    except:
        print("SSH service is not running or not accessible.")

# ...

### 4. Telnet Check
def check_telnet():
    try:
        telnet = telnetlib.Telnet('192.168.64.7')
        print("Telnet service is running and accessible.")
        telnet.close()
    except:
        print("Telnet service is not running or not accessible.")

# ...

### 5. SMTP Check
def check_smtp():
    try:
        smtp = smtplib.SMTP('192.168.64.7')
        smtp.helo()
        print("SMTP service is running and accessible.")
        smtp.quit()
    except:
        print("SMTP service is not running or not accessible.")

# ...

### 6. DNS Check
def check_dns():
    try:
        dns = dns.resolver.Resolver()
        dns.nameservers = ['192.168.64.7']
        answer = dns.query('example.com', 'A')
        print("DNS service is running and accessible.")
    except:
        print("DNS service is not running or not accessible.")

# ...

### 7. HTTP Check
def check_http():
    try:
        http = http.client.HTTPConnection('192.168.64.7')
        http.request('GET', '/')
        response = http.getresponse()
        print("HTTP service is running and accessible.")
        http.close()
    except:
        print("HTTP service is not running or not accessible.")

# ...

### 8. RPC Check
def check_rpc():
    try:
        rpc = xmlrpclib.ServerProxy('http://192.168.64.7/')
        rpc.system.listMethods()
        print("RPC service is running and accessible.")
    except:
        print("RPC service is not running or not accessible.")

# ...

### 9. Samba Check
def check_samba():
    try:
        samba = smb.SMB('192.168.64.7')
        samba.login('username', 'password')
        print("Samba service is running and accessible.")
        samba.close()
    except:
        print("Samba service is not running or not accessible.")

# ...

### 10. Login Service Check
def check_login_service():
    try:
        login = telnetlib.Telnet('192.168.64.7', 23)
        login.read_until(b'login: ')
        login.write(b'root\n')
        login.read_until(b'Password: ')
        login.write(b'password\n')
        login.read_until(b'#')
        print("Login service is running and accessible.")
        login.close()
    except:
        print("Login service is not running or not accessible.")

# ...

### 11. NFS Check
def check_nfs():
    try:
        nfs = nfs.NFS('192.168.64.7')
        nfs.mount()
        print("NFS service is running and accessible.")
        nfs.umount()
    except:
        print("NFS service is not running or not accessible.")

# ...

### 12. ProFTPD Check
def check_proftpd():
    try:
        proftpd = ftplib.FTP('192.168.64.7')
        proftpd.login()
        print("ProFTPD service is running and accessible.")
        proftpd.quit()
    except:
        print("ProFTPD service is not running or not accessible.")

# ...

### 13. MySQL Check
def check_mysql():
    try:
        mysql = MySQLdb.connect('192.168.64.7', 'root', 'password', 'mysql')
        print("MySQL service is running and accessible.")
        mysql.close()
    except:
        print("MySQL service is not running or not accessible.")

# ...

### 14. Main Function
def main():
    check_ftp()
    check_ssh()
    check_telnet()
    check_smtp()
    check_dns()
    check_http()
    check_rpc()
    check_samba()
    check_login_service()
    check_nfs()
    check_proftpd()
    check_mysql()

if __name__ == '__main__':
    main()

### 15. Run the script
python pentest_check.py

### 16. Output