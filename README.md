# Directadmin 1.61.3 License 2038
 
 Centos 7 minimum

**Install the necessary applications before the installation DA 2038**

yum install wget tar gcc gcc-c++ flex bison make bind bind-libs bind-utils openssl openssl-devel perl quota libaio \
libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel \
psmisc net-tools systemd-devel libdb-devel perl-DBI perl-Perl4-CoreLibs perl-libwww-perl xfsprogs rsyslog logrotate crontabs file kernel-headers net-tools

**Install DirectAdmin 2038**

wget https://raw.githubusercontent.com/NOTAD/DirectAdmin-1.61.3-key-2038/main/update1613-CentOS7.sh

chmod 755 update1613-CentOS7.sh

./update1613-CentOS7.sh

**Config IP License**

*If your interface is **ensXXX** change **eth0** to **ensXXX***

ifconfig eth0:100 176.99.3.34 netmask 255.255.255.0 up

echo 'DEVICE=eth0:100' >> /etc/sysconfig/network-scripts/ifcfg-eth0:100

echo 'IPADDR=176.99.3.34' >> /etc/sysconfig/network-scripts/ifcfg-eth0:100

echo 'NETMASK=255.255.255.0' >> /etc/sysconfig/network-scripts/ifcfg-eth0:100

service network restart

/usr/bin/perl -pi -e 's/^ethernet_dev=.*/ethernet_dev=eth0:100/' /usr/local/directadmin/conf/directadmin.conf

**Get Key 2038**

service directadmin stop

cd /usr/local/directadmin/conf

wget -O license.key https://raw.githubusercontent.com/NOTAD/DirectAdmin-1.61.3-key-2038/main/license.key

chown diradmin:diradmin license.key

chmod 600 license.key

**Complete the installation**

service directadmin start 

systemctl disable firewalld

systemctl stop firewalld

init 6

