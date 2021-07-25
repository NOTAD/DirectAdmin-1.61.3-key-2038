#!/bin/sh

###############################################################################
# setup.sh
# DirectAdmin  setup.sh  file  is  the  first  file  to  download  when doing a
# DirectAdmin Install.   It  will  ask  you  for  relevant information and will
# download  all  required  files.   If  you  are unable to run this script with
# ./setup.sh  then  you probably need to set it's permissions.  You can do this
# by typing the following:
#
# chmod 755 setup.sh
#
# after this has been done, you can type ./setup.sh to run the script.
#
###############################################################################

OS=`uname`;

if [ "$(id -u)" != "0" ]; then
	echo "You must be root to execute the script. Exiting."
	exit 1
fi

#For FreeBSD 11
if [ ! -e /usr/bin/perl ] && [ -e /usr/local/bin/perl ]; then
	ln -s /usr/local/bin/perl /usr/bin/perl
fi

if [ "$OS" = "FreeBSD" ]; then
	WGET_PATH=/usr/local/bin/wget
else
	WGET_PATH=/usr/bin/wget
fi

if [ ! -e /usr/bin/perl ] || [ ! -e ${WGET_PATH} ]; then

	if [ "${OS}" = "FreeBSD" ]; then
		pkg install -y perl5 wget
		rehash
	elif [ -e /etc/debian_version ]; then
		apt-get -y install perl wget
	else
		yum -y install perl wget
	fi

	if [ ! -e /usr/bin/perl ]; then
		echo "Cannot find perl. Please run pre-install commands:";
		echo "    https://help.directadmin.com/item.php?id=354";
		exit 1;
	fi

	if [ ! -e ${WGET_PATH} ]; then
		echo "Cannot find ${WGET_PATH}. Please run pre-install commands:";
		echo "    https://help.directadmin.com/item.php?id=354";
		exit 80;
	fi
fi

#For FreeBSD 11
if [ ! -e /usr/bin/perl ] && [ -e /usr/local/bin/perl ]; then
        ln -s /usr/local/bin/perl /usr/bin/perl
fi

random_pass() {
	PASS_LEN=`perl -le 'print int(rand(6))+9'`
	START_LEN=`perl -le 'print int(rand(8))+1'`
	END_LEN=$(expr ${PASS_LEN} - ${START_LEN})
	SPECIAL_CHAR=`perl -le 'print map { (qw{@ ^ _ - /})[rand 6] } 1'`;
	NUMERIC_CHAR=`perl -le 'print int(rand(10))'`;
	PASS_START=`perl -le "print map+(A..Z,a..z,0..9)[rand 62],0..$START_LEN"`;
	PASS_END=`perl -le "print map+(A..Z,a..z,0..9)[rand 62],0..$END_LEN"`;
	PASS=${PASS_START}${SPECIAL_CHAR}${NUMERIC_CHAR}${PASS_END}
	echo $PASS
}

ADMIN_USER=admin
DB_USER=da_admin
#ADMIN_PASS=`perl -le'print map+(A..Z,a..z,0..9)[rand 62],0..9'`;
ADMIN_PASS=`random_pass`
#RAND_LEN=`perl -le'print 16+int(rand(9))'`
#DB_ROOT_PASS=`perl -le"print map+(A..Z,a..z,0..9)[rand 62],0..$RAND_LEN"`;
DB_ROOT_PASS=`random_pass`
DOWNLOAD_BETA=false
if [ "$1" = "beta" ] || [ "$2" = "beta" ]; then
	DOWNLOAD_BETA=true
fi

FTP_HOST=files.directadmin.com

WGET_OPTION="--no-dns-cache";
COUNT=`$WGET_PATH --help | grep -c no-check-certificate`
if [ "$COUNT" -ne 0 ]; then
	WGET_OPTION="--no-check-certificate ${WGET_OPTION}";
fi

SYSTEMD=no
SYSTEMDDIR=/etc/systemd/system
if [ -d ${SYSTEMDDIR} ]; then
	if [ -e /bin/systemctl ] || [ -e /usr/bin/systemctl ]; then
		SYSTEMD=yes
	fi
fi

CID=0
LID=0
HOST=`hostname -f`;
if [ "${HOST}" = "" ]; then
	if [ -x /usr/bin/hostnamectl ]; then
		HOST=`/usr/bin/hostnamectl status | grep 'hostname:' | grep -v 'n/a' | head -n1 | awk '{print $3}'`
	fi
fi

CMD_LINE=0
AUTO=0
ETH_DEV=eth0
IP=0
OS_OVERRIDE_FILE=/root/.os_override

GET_LICENSE=1
if [ -s /root/.skip_get_license ]; then
	GET_LICENSE=0
fi

if [ $# -gt 0 ]; then
case "$1" in
	--help|help|\?|-\?|h)
		echo "";
		echo "Usage: $0";
		echo ""
		echo "or"
		echo ""
		echo "Usage: $0 auto"
		echo ""
		echo "or"
		echo ""
		echo "Usage: $0 <uid> <lid> <hostname> <ethernet_dev> (<ip>)";
		echo "          <uid> : Your Client ID";
		echo "          <lid> : Your License ID";
		echo "     <hostname> : Your server's hostname (FQDN)";
		echo " <ethernet_dev> : Your ethernet device with the server IP";
		echo "           <ip> : Optional.  Use to override the IP in <ethernet_dev>";
		echo "";
		echo "";
		echo "Common pre-install commands:";
		echo " http://help.directadmin.com/item.php?id=354";
		exit 0;
		;;
esac

	if [ "$1" = "auto" ]; then
		AUTO=1
		CMD_LINE=1
		LID_INFO=/root/.lid_info

		#cleanup
		rm -f /root/.lan
		rm -f ${LID_INFO}

		${WGET_PATH} ${WGET_OPTION} -O ${LID_INFO} https://www.directadmin.com/clients/my_license_info.php
		if [ ! -s ${LID_INFO} ]; then
			echo "Error getting license info. Empty ${LID_INFO} file. Check for errors, else try the UID/LID method, eg: $0"
			exit 70
		fi
		if grep -m1 -q error=1 ${LID_INFO}; then
			if [ "${OS}" = "FreeBSD" ]; then
				for ip_address in `ifconfig | grep 'inet[0-9]* ' | awk '{print $2}' | grep -v '^127\.0\.0\.1' | grep -v '^::1' | grep -v '^fe80'`; do {
					${WGET_PATH} ${WGET_OPTION} --bind-address="${ip_address}" -O ${LID_INFO} https://www.directadmin.com/clients/my_license_info.php
					if ! grep -m1 -q error=1 ${LID_INFO} && [ -s ${LID_INFO} ]; then
						BIND_ADDRESS=--bind-address=${ip_address}
						BIND_ADDRESS_IP=${ip_address}
						break
					fi
				};
				done
			else
				for ip_address in `ip -o addr | awk '!/^[0-9]*: ?lo|link\/ether/ {print $4}' | cut -d/ -f1 | grep -v ^fe80`; do {
					${WGET_PATH} ${WGET_OPTION} --bind-address="${ip_address}" -O ${LID_INFO} https://www.directadmin.com/clients/my_license_info.php
					if ! grep -m1 -q error=1 ${LID_INFO} && [ -s ${LID_INFO} ]; then
						BIND_ADDRESS=--bind-address=${ip_address}
						BIND_ADDRESS_IP=${ip_address}
						break
					fi
				};
				done
			fi
		fi
		if grep -m1 -q error=1 ${LID_INFO}; then
			echo "An error has occured. Info about the error:"
			grep ^text= ${LID_INFO} | cut -d= -f2

			if [ "${GET_LICENSE}" = "1" ]; then
				exit 71
			fi
			echo "However, we're skipping the license download, so we'll continue anyway"
		fi
		CID=`grep ^uid= ${LID_INFO} |cut -d= -f2`
		LID=`grep ^lid= ${LID_INFO} |cut -d= -f2`
		IP=`grep ^ip=   ${LID_INFO} |cut -d= -f2`
		HOST=`grep ^hostname= ${LID_INFO} |cut -d= -f2`
		LID_OS=`grep ^os= ${LID_INFO} |cut -d= -f2`

		USE_HOST=/root/.use_hostname
		if [ -e ${USE_HOST} ]; then
			HOST=`cat ${USE_HOST} | head -n 1`
		fi

		if [ "${HOST}" = "" ]; then
			HOST=`hostname -f`
		fi
		if [ "${HOST}" = "localhost" ]; then
			echo "'localhost' is not valid for the hostname. Setting it to server.hostname.com, you can change it later in Admin Settings"
			HOST=server.hostname.com
		fi
		if [ "${HOST}" != "" ]; then
			C=`echo ${HOST} | grep -o '\.' | grep -c '\.'`
			if [ "${C}" = "0" ]; then
				echo "'${HOST}' is not valid for the hostname. Setting it to server.hostname.com, you can change it later in Admin Settings"
				HOST=server.hostname.com			
			fi
		fi

		if [ "$OS" = "FreeBSD" ]; then
			EDEVS=`ifconfig -l`
			for i in $EDEVS; do
			{
				DC=`ifconfig $i | grep -c "inet $IP "`
				if [ "${DC}" -gt 0 ]; then
					ETH_DEV=$i
					break
				fi
			};
			done;
		else
			ETH_DEV=`ip addr | grep " $IP/" | awk '{print $NF}'`
		fi
		if [ -z "${ETH_DEV}" ]; then
			if [ "${OS}" != "FreeBSD" ]; then
				ETH_DEV_TEMP=`ip link | grep -v 'lo:' | grep -m1 '^[0-9]:' | cut -d: -f2 | awk '{print $1}'`
				if [ ! -z "${ETH_DEV_TEMP}" ]; then
					ETH_DEV="${ETH_DEV_TEMP}"
					LAN_AUTO=1
					echo 1 > /root/.lan
				fi
			fi
		fi
		if [ "${LID_OS}" = "Linux+64+static" ] && [ "${OS}" != "FreeBSD" ]; then
			echo -n "${LID_OS}" > ${OS_OVERRIDE_FILE}
		fi

		if [ "${GET_LICENSE}" = "0" ]; then
			if [ "${CID}" = "" ]; then
				CID=0
			fi
			if [ "${LID}" = "" ]; then
				LID=0
			fi
			if [ "${IP}" = "" ]; then
				IP=`wget -q -O - http://myip.directadmin.com`
			fi
		fi
	else
		CID=$1;
		LID=$2;
		HOST=$3;
		if [ $# -lt 4 ]; then
			$0 --help
			exit 56;
		fi

		ETH_DEV=$4;
		CMD_LINE=1;
		if [ $# -gt 4 ]; then
			IP=$5;
		fi
	fi
fi

B64=0
if [ "$OS" = "FreeBSD" ]; then
	B64=`uname -m | grep -c 64`

	if [ "$B64" -gt 0 ]; then
		echo "*** 64-bit OS ***";
		echo "*** that being said, this should be a FreeBSD 7, 8, 9, 11, or 12 system. ***";
		sleep 2;
		B64=1
	fi
else
	B64=`uname -m | grep -c 64`
	if [ "$B64" -gt 0 ]; then
		echo "*** 64-bit OS ***";
		echo "";
		sleep 2;
		B64=1
	fi
fi

if [ -e /usr/local/directadmin/conf/directadmin.conf ]; then
	echo "";
	echo "";
	echo "*** DirectAdmin already exists ***";
	echo "    Press Ctrl-C within the next 10 seconds to cancel the install";
	echo "    Else, wait, and the install will continue, but will destroy existing data";
	echo "";
	echo "";
	sleep 10;
fi

if [ -e /usr/local/cpanel ]; then
        echo "";
        echo "";
        echo "*** CPanel exists on this system ***";
        echo "    Press Ctrl-C within the next 10 seconds to cancel the install";
        echo "    Else, wait, and the install will continue overtop (as best it can)";
        echo "";
        echo "";
        sleep 10;
fi

OS_VER=;

REDHAT_RELEASE=/etc/redhat-release
DEBIAN_VERSION=/etc/debian_version
DA_PATH=/usr/local/directadmin
CB_VER=2.0
CB_OPTIONS=${DA_PATH}/custombuild/options.conf
SCRIPTS_PATH=$DA_PATH/scripts
PACKAGES=$SCRIPTS_PATH/packages
SETUP=$SCRIPTS_PATH/setup.txt

SERVER=http://files.directadmin.com/services
BFILE=$SERVER/custombuild/${CB_VER}/custombuild/build
CBPATH=$DA_PATH/custombuild
BUILD=$CBPATH/build

if [ $OS = "FreeBSD" ]; then
	OS_VER=`uname -r | cut -d- -f1`
elif [ -e $DEBIAN_VERSION ]; then
	OS=debian
	OS_VER=`cat $DEBIAN_VERSION | head -n1`
	if [ "$OS_VER" = "testing/unstable" ]; then
		OS_VER=3.1
	fi
	if [ "$OS_VER" = "lenny/sid" ]; then
		OS_VER=5.0
	fi
	if [ "$OS_VER" = "squeeze/sid" ]; then
		OS_VER=6.0
		#should be 6.0, but used to be 5.
	fi
	if [ "$OS_VER" = "wheezy/sid" ]; then
		OS_VER=7.0
	fi

	if [ "$OS_VER" = "jessie/sid" ]; then
		OS_VER=8.0
	fi

	if [ "$OS_VER" = "stretch/sid" ]; then
		OS_VER=9.0
	fi

	if [ "$OS_VER" = "buster/sid" ]; then
		echo "This appears to be Debian version $OS_VER which is Debian 10";
		OS_VER=10.0
	fi

	if [ "$OS_VER" = "bullseye/sid" ]; then
		echo "This appears to be Debian version $OS_VER which is Debian 11";
		OS_VER=11.0
	fi

else
	OS_VER=`cat /etc/redhat-release | head -n1 | cut -d\  -f5`
fi

if [ "$OS_VER" = "release" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release | cut -d\  -f6 | cut -d. -f1,2`
elif [ "$OS_VER" = "ES" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release | cut -d\  -f7`
elif [ "$OS_VER" = "WS" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release | cut -d\  -f7`
elif [ "$OS_VER" = "AS" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release | cut -d\  -f7`
elif [ "$OS_VER" = "Server" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release | head -n1 | cut -d\  -f7`
elif [ "`cat /etc/redhat-release 2>/dev/null| cut -d\  -f1`" = "CentOS" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release |cut -d\  -f3`;
	if [ "$OS_VER" = "release" ]; then
		OS_VER=`cat /etc/redhat-release | cut -d\  -f4`
	fi
	OS_VER=`echo $OS_VER | cut -d. -f1,2`
elif [ "`cat /etc/redhat-release 2>/dev/null| cut -d\  -f3`" = "Enterprise" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release 2>/dev/null| cut -d\  -f7`
elif [ "`cat /etc/redhat-release 2>/dev/null| cut -d\  -f1,2`" = "CloudLinux Server" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release 2>/dev/null| cut -d\  -f4`
elif [ "`cat /etc/redhat-release 2>/dev/null| cut -d\  -f1,2`" = "CloudLinux release" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release 2>/dev/null| cut -d\  -f3`
elif [ "`cat /etc/redhat-release 2>/dev/null| cut -d\  -f1,2`" = "Scientific Linux" ]; then
	OS=Enterprise
	OS_VER=`cat /etc/redhat-release 2>/dev/null| cut -d\  -f4`
elif [ "`cat ${REDHAT_RELEASE} 2>/dev/null| cut -d\  -f5`" = "Enterprise" ]; then
	#Derived from Red Hat Enterprise Linux 7.1 (Source)
	OS=Enterprise
	OS_VER=`cat ${REDHAT_RELEASE} 2>/dev/null| cut -d\  -f7`
fi

OS_MAJ_VER=`echo $OS_VER | cut -d. -f1`

# Get the services file name:
# services72.tar.gz
# services73.tar.gz
# services80.tar.gz
# services90.tar.gz
# services_freebsd48.tar.gz

SERVICES="";
OS_NAME=
if [ "$OS" = "debian" ]; then
	OS_VER=`echo $OS_VER | cut -d. -f1,2`
	if [ "$B64" -eq 1 ]; then
		case "$OS_MAJ_VER" in
			5)	SERVICES=services_debian50_64.tar.gz
				;;
			6)	SERVICES=services_debian60_64.tar.gz
				;;
			7)	SERVICES=services_debian70_64.tar.gz
				OS_NAME=Debian+7+64
				;;
			8)	SERVICES=services_debian80_64.tar.gz
				OS_NAME=Debian+8+64
				;;
			9)	SERVICES=services_debian90_64.tar.gz
				OS_NAME=Debian+9+64
				;;
			10)	SERVICES=services_debian100_64.tar.gz
				OS_NAME=Debian+10+64
				;;
			11)	SERVICES=services_debian110_64.tar.gz
				OS_NAME=Debian+11+64
				;;
			*)	SERVICES=services_debian100_64.tar.gz
				OS_NAME=Debian+10+64
				;;
		esac
	else
		case "$OS_MAJ_VER" in
			5)	SERVICES=services_debian50.tar.gz
				;;
			6)	SERVICES=services_debian60.tar.gz
				;;
			7)	SERVICES=services_debian70.tar.gz
				OS_NAME=Debian+7
				;;
			8)	SERVICES=services_debian80.tar.gz
						echo "************";
						echo "This is a 32-bit install of Debian 8.";
						echo "We currently only support the 64-bit version of Debian 8.";
						echo "If you wish to use this OS version, please install the 64-bit version.";
						echo "";
						exit 1;
				;;
			9|10)	SERVICES=services_debian90.tar.gz
                                                echo "************";
                                                echo "This is a 32-bit install of Debian $OS_VER.";
                                                echo "We currently only support the 64-bit version of Debian $OS_VER.";
                                                echo "If you wish to use this OS version, please install the 64-bit version.";
                                                echo "";
                                                exit 1;
				;;
			*)	SERVICES=services_debian70.tar.gz
				OS_NAME=Debian+7
				;;
		esac
	fi

elif [ "$OS" = "FreeBSD" ] && [ "$B64" -eq 0 ]; then
	case "$OS_MAJ_VER" in
		9)	SERVICES=services_freebsd90.tar.gz
			OS_NAME=FreeBSD+9.1+32
			;;
	esac
elif [ "$OS" = "FreeBSD" ] && [ "$B64" -eq 1 ]; then
        case "$OS_MAJ_VER" in
                7)	SERVICES=services_freebsd71_64.tar.gz
                        ;;
		8)	SERVICES=services_freebsd80_64.tar.gz
			;;
		9)	SERVICES=services_freebsd90_64.tar.gz
			OS_NAME=FreeBSD+9.0+64
			;;
		11)	SERVICES=services_freebsd110_64.tar.gz
			OS_NAME=FreeBSD+11.0+64
			;;
		12)	SERVICES=services_freebsd120_64.tar.gz
			OS_NAME=FreeBSD+12.0+64
			;;
        esac
elif [ $B64 -eq 1 ]; then
	case "$OS_MAJ_VER" in
		4)	SERVICES=services_es41_64.tar.gz
			;;
		5)	SERVICES=services_es50_64.tar.gz
			OS_NAME=ES+5.0+64
			;;
		6)	SERVICES=services_es60_64.tar.gz
			OS_NAME=ES+6.0+64
			;;
		7)	SERVICES=services_es70_64.tar.gz
			OS_NAME=ES+7.0+64
			;;
		8)	SERVICES=services_es80_64.tar.gz
			OS_NAME=ES+8.0+64
			;;
	esac
else
	case "$OS_MAJ_VER" in
		5)	SERVICES=services_es50.tar.gz
			OS_NAME=ES+5.0
			;;
		6)	SERVICES=services_es60.tar.gz
			OS_NAME=ES+6.0
			;;
		7)	SERVICES=services_es70.tar.gz
			;;
	esac

fi

if [ "$SERVICES" = "" ]; then

	yesno="n";
	while [ $yesno = "n" ];
	do
	{
		echo "";
		echo "*** Unable to determine which services pack to use ***";
		echo "";
		echo "Please type in the file name closest to your system from the following list:";
		echo "";
		echo "RHEL/CentOS:";
		echo "  services_es60.tar.gz";
		echo "  services_es60_64.tar.gz";
		echo "  services_es70_64.tar.gz";
		echo "  services_es80_64.tar.gz";
		echo "";
		echo "FreeBSD:";
		echo "  services_freebsd90_64.tar.gz";
		echo "  services_freebsd110_64.tar.gz";
		echo "";
		echo "Debian:";
		echo "  services_debian80_64.tar.gz";
		echo "  services_debian90_64.tar.gz";
		echo "  services_debian100_64.tar.gz";
		echo "";

		echo -n "Type the filename: ";
		read SERVICES

		echo "";
		echo "Value entered: $SERVICES";

	        echo -n "Is this correct? (y,n) : ";
	        read yesno;
	}
	done;

fi

/bin/mkdir -p $PACKAGES

yesno=n;
preinstall=n;
if [ "$CMD_LINE" -eq 1 ] || [ "${AUTO}" -eq 1 ]; then
	yesno=y;
	if [ -e /root/.preinstall ] || [ "${AUTO}" -eq 1 ]; then
		preinstall=y;
	fi
else
	echo "*****************************************************";
	echo "*";
	echo "* DirectAdmin requires certain packages, described here:";
	echo "*   http://help.directadmin.com/item.php?id=354";
	echo "*";
	echo -n "* Would you like to install these required pre-install packages? (y/n): ";

	read preinstall;

	echo "*";
fi

	if [ "$preinstall" = "y" ]; then
		echo "* Installing pre-install packages ....";
		if [ "$OS" = "FreeBSD" ]; then
			if [ "${OS_MAJ_VER}" -ge 12 ]; then
				pkg install -y gcc gmake perl5 wget bison flex cyrus-sasl cmake python autoconf libtool libarchive iconv bind911 mailx webalizer gettext-runtime udns sudo psmisc tar openssl krb5
			elif [ "${OS_MAJ_VER}" -ge 11 ]; then
				pkg install -y gcc gmake perl5 wget bison flex cyrus-sasl cmake python autoconf libtool libarchive iconv bind911 mailx webalizer gettext-runtime psmisc tar
			elif [ "${OS_MAJ_VER}" -ge 10 ]; then
				pkg install -y gcc gmake perl5 wget bison flex cyrus-sasl cmake python autoconf libtool libarchive iconv bind99 mailx psmisc
			else
				pkg_add -r gmake perl wget bison flex gd cyrus-sasl2 cmake python autoconf libtool libarchive mailx
			fi
		elif [ "$OS" = "debian" ]; then
			if [ "${OS_MAJ_VER}" -ge 10 ]; then
				apt-get -y update
				apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libperl4-corelibs-perl libwww-perl libaio1 libaio-dev \
					zlib1g zlib1g-dev libcap-dev cron bzip2 zip automake autoconf libtool cmake pkg-config python libdb-dev libsasl2-dev \
					libncurses5 libncurses5-dev libsystemd-dev bind9 dnsutils quota patch logrotate rsyslog libc6-dev libexpat1-dev \
					libcrypt-openssl-rsa-perl libnuma-dev libnuma1
			elif [ "${OS_MAJ_VER}" -ge 9 ]; then
				apt-get -y update
				apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libperl4-corelibs-perl libaio1 libaio-dev zlib1g zlib1g-dev libcap-dev cron bzip2 zip automake autoconf libtool cmake pkg-config python libdb-dev libsasl2-dev libncurses5-dev libsystemd-dev bind9 dnsutils quota patch libjemalloc-dev logrotate rsyslog libc6-dev libexpat1-dev libcrypt-openssl-rsa-perl libnuma-dev libnuma1
			elif [ "${OS_MAJ_VER}" -ge 8 ]; then
				apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libaio1 libaio-dev \
					zlib1g zlib1g-dev libcap-dev cron bzip2 automake autoconf libtool cmake pkg-config python libdb-dev libsasl2-dev \
					libncurses5-dev libsystemd-dev bind9 dnsutils quota libsystemd-daemon0 patch libjemalloc-dev logrotate rsyslog libc6-dev systemd systemd-sysv
			elif [ "${OS_MAJ_VER}" -eq 7 ]; then
				apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libaio1 libaio-dev zlib1g zlib1g-dev libcap-dev cron bzip2 automake autoconf libtool cmake pkg-config python libdb-dev libsasl2-dev libncurses5-dev patch libjemalloc-dev
			else
				apt-get -y install gcc g++ make flex bison openssl libssl-dev perl perl-base perl-modules libperl-dev libaio1 libaio-dev zlib1g zlib1g-dev libcap-dev cron bzip2 automake autoconf libtool cmake pkg-config python libreadline-dev libdb4.8-dev libsasl2-dev patch
			fi
		else
			if [ "${OS_MAJ_VER}" -ge 8 ]; then
				yum -y install wget tar gcc gcc-c++ flex bison make bind bind-libs bind-utils openssl openssl-devel perl quota libaio \
					libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
					autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel \
					psmisc net-tools systemd-devel libdb-devel perl-DBI perl-libwww-perl xfsprogs rsyslog logrotate crontabs file \
					kernel-headers hostname
			elif [ "${OS_MAJ_VER}" -ge 7 ]; then
				yum -y install wget tar gcc gcc-c++ flex bison make bind bind-libs bind-utils openssl openssl-devel perl quota libaio \
					libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
					autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel \
					psmisc net-tools systemd-devel libdb-devel perl-DBI perl-Perl4-CoreLibs perl-libwww-perl xfsprogs rsyslog logrotate crontabs file kernel-headers
			else
				yum -y install wget tar gcc gcc-c++ flex bison make bind bind-libs bind-utils openssl openssl-devel perl quota libaio \
					libcom_err-devel libcurl-devel gd zlib-devel zip unzip libcap-devel cronie bzip2 cyrus-sasl-devel perl-ExtUtils-Embed \
					autoconf automake libtool which patch mailx bzip2-devel lsof glibc-headers kernel-devel expat-devel db4-devel
			fi
		fi
	else
		echo "* skipping pre-install packages.";
		echo "* We then assume that you've already installed them.";
		echo "* If you have not, then ctrl-c and install them (or-rerun the setup.sh):";
		echo "*   http://help.directadmin.com/item.php?id=354";

	fi
	echo "*";
	echo "*****************************************************";
	echo "";

while [ "$yesno" = "n" ];
do
{
	echo -n "Please enter your Client ID : ";
	read CID;

	echo -n "Please enter your License ID : ";
	read LID;

	echo "Please enter your hostname (server.domain.com)";
	echo "It must be a Fully Qualified Domain Name";
	echo "Do *not* use a domain you plan on using for the hostname:";
	echo "eg. don't use domain.com. Use server.domain.com instead.";
	echo "Do not enter http:// or www";
	echo "";

	echo "Your current hostname is: ${HOST}";
	echo "Leave blank to use your current hostname";
	OLD_HOST=$HOST
	echo "";
	echo -n "Enter your hostname (FQDN) : ";
	read HOST;
	if [ "$HOST" = "" ]; then
		HOST=$OLD_HOST
	fi

	echo "Client ID:  $CID";
	echo "License ID: $LID";
	echo "Hostname: $HOST";
	echo -n "Is this correct? (y,n) : ";
	read yesno;
}
done;


############

# Get the other info
EMAIL=${ADMIN_USER}@${HOST}
if [ -s /root/.email.txt ]; then
	EMAIL=`cat /root/.email.txt | head -n 1`
fi

TEST=`echo $HOST | cut -d. -f3`
if [ "$TEST" = "" ]
then
        NS1=ns1.`echo $HOST | cut -d. -f1,2`
        NS2=ns2.`echo $HOST | cut -d. -f1,2`
else
        NS1=ns1.`echo $HOST | cut -d. -f2,3,4,5,6`
        NS2=ns2.`echo $HOST | cut -d. -f2,3,4,5,6`
fi

if [ -s /root/.ns1.txt ] && [ -s /root/.ns2.txt ]; then
	NS1=`cat /root/.ns1.txt | head -n1`
	NS2=`cat /root/.ns2.txt | head -n1`
fi

## Get the ethernet_dev

clean_dev()
{
	C=`echo $1 | grep -o ":" | wc -l`

	if [ "${C}" -eq 0 ]; then
		echo $1;
		return;
	fi

	if [ "${C}" -ge 2 ]; then
		echo $1 | cut -d: -f1,2
		return;
	fi

	TAIL=`echo $1 | cut -d: -f2`
	if [ "${TAIL}" = "" ]; then
		echo $1 | cut -d: -f1
		return;
	fi

	echo $1
}


if [ "$OS" = "FreeBSD" ]; then

	if [ $CMD_LINE -eq 0 ]; then

		DEVS=`/sbin/ifconfig -a | grep -e "^[a-z]" | cut -d: -f1 |grep -v lp0|grep -v lo0|grep -v tun0|grep -v sl0|grep -v ppp0|grep -v faith0`

		COUNT=0;
		for i in $DEVS; do
		{
			COUNT=$(($COUNT+1));
		};
		done;

		if [ $COUNT -eq 0 ]; then
        		echo "Could not find your ethernet device.";
	        	echo -n "Please enter the name of your ethernet device: ";
	        	read ETH_DEV;
		elif [ $COUNT -eq 1 ]; then
        		echo -n "Is $DEVS your network adaptor with the license IP? (y,n) : ";
		        read yesno;
        		if [ "$yesno" = "n" ]; then
                		echo -n "Enter the name of the ethernet device you wish to use : ";
		                read ETH_DEV;
		        else
	        	        ETH_DEV=$DEVS
		        fi
		else
	        	# more than one
		        echo "The following ethernet devices were found. Please enter the name of the one you wish to use:";
		        echo "";
		        echo $DEVS;
		        echo "";
		        echo -n "Enter the device name: ";
		        read ETH_DEV;
		fi
	fi

	echo "Using $ETH_DEV";

	if [ "$IP" = "0" ]; then

		IP=`/sbin/ifconfig $ETH_DEV | grep 'inet ' | head -n1 | cut -d\  -f2`
	fi

	echo "Using $IP";

	NM_HEX=`/sbin/ifconfig $ETH_DEV | grep 'inet ' | head -n1 | cut -d\  -f4 | cut -dx -f2 | tr '[a-f]' '[A-F]'`

	NMH1=`echo $NM_HEX | awk '{print substr($1,1,2)}'`
	NMH2=`echo $NM_HEX | awk '{print substr($1,3,2)}'`
	NMH3=`echo $NM_HEX | awk '{print substr($1,5,2)}'`
	NMH4=`echo $NM_HEX | awk '{print substr($1,7,2)}'`

	NM1=`echo "ibase=16; $NMH1" | bc`
	NM2=`echo "ibase=16; $NMH2" | bc`
	NM3=`echo "ibase=16; $NMH3" | bc`
	NM4=`echo "ibase=16; $NMH4" | bc`

	NM=$NM1.$NM2.$NM3.$NM4;

else
	if [ $CMD_LINE -eq 0 ]; then
		DEVS=`ip link show | grep -e "^[1-9]" | awk '{print $2}' | cut -d: -f1 | grep -v lo | grep -v sit0 | grep -v ppp0 | grep -v faith0`
		if [ -z "${DEVS}" ] && [ -x /sbin/ifconfig ]; then
			DEVS=`/sbin/ifconfig -a | grep -e "^[a-z]" | awk '{ print $1; }' | grep -v lo | grep -v sit0 | grep -v ppp0 | grep -v faith0`
		fi
		COUNT=0;
		for i in $DEVS; do
		{
			COUNT=$(($COUNT+1));
		};
		done;

		if [ $COUNT -eq 0 ]; then
        		echo "Could not find your ethernet device.";
	        	echo -n "Please enter the name of your ethernet device: ";
	        	read ETH_DEV;
		elif [ $COUNT -eq 1 ]; then

			#DIP=`/sbin/ifconfig $DEVS | grep 'inet addr:' | cut -d: -f2 | cut -d\  -f1`;
			DEVS=`clean_dev $DEVS`
			DIP=`ip addr show $DEVS | grep -m1 'inet ' | awk '{print $2}' | cut -d/ -f1`
			#ifconfig fallback
			if [ -z "${DIP}" ] && [ -x /sbin/ifconfig ]; then
				DIP=`/sbin/ifconfig $DEVS | grep 'inet ' | awk '{print $2}' | cut -d: -f2`;
			fi

        		echo -n "Is $DEVS your network adaptor with the license IP ($DIP)? (y,n) : ";
		        read yesno;
        		if [ "$yesno" = "n" ]; then
                		echo -n "Enter the name of the ethernet device you wish to use : ";
		                read ETH_DEV;
		        else
	        	        ETH_DEV=$DEVS
		        fi
		else
	        	# more than one
		        echo "The following ethernet devices/IPs were found. Please enter the name of the device you wish to use:";
		        echo "";
		        #echo $DEVS;
		        for i in $DEVS; do
		        {
				D=`clean_dev $i`
				DIP=`ip addr show $D | grep -m1 'inet ' | awk '{print $2}' | cut -d/ -f1`
				if [ -z "${D}" ] && [ -x /sbin/ifconfig ]; then
					DIP=`/sbin/ifconfig $D | grep 'inet ' | awk '{print $2}' | cut -d: -f2`;
				fi
		        	echo "$D       $DIP";
		        };
		        done;

		        echo "";
		        echo -n "Enter the device name: ";
		        read ETH_DEV;
		fi
	fi

	if [ "$IP" = "0" ]; then
		#IP=`/sbin/ifconfig $ETH_DEV | grep 'inet addr:' | cut -d: -f2 | cut -d\  -f1`;
		IP=`ip addr show $ETH_DEV | grep -m1 'inet ' | awk '{print $2}' | cut -d/ -f1`
		if [ -z "${IP}" ] && [ -x /sbin/ifconfig ]; then
			IP=`/sbin/ifconfig $ETH_DEV | grep 'inet ' | awk '{print $2}' | cut -d: -f2`;
		fi
	fi

	prefixToNetmask(){
        BINARY_IP=""
        for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32; do {
                if [ ${i} -le ${1} ]; then
                        BINARY_IP="${BINARY_IP}1"
                else
                        BINARY_IP="${BINARY_IP}0"
                fi
        }
        done

        B1=`echo ${BINARY_IP} | cut -c1-8`
        B2=`echo ${BINARY_IP} | cut -c9-16`
        B3=`echo ${BINARY_IP} | cut -c17-24`
        B4=`echo ${BINARY_IP} | cut -c25-32`
        NM1=`perl -le "print ord(pack('B8', '${B1}'))"`
        NM2=`perl -le "print ord(pack('B8', '${B2}'))"`
        NM3=`perl -le "print ord(pack('B8', '${B3}'))"`
        NM4=`perl -le "print ord(pack('B8', '${B4}'))"`

        echo "${NM1}.${NM2}.${NM3}.${NM4}"
	}

	PREFIX=`ip addr show ${ETH_DEV} | grep -m1 'inet ' | awk '{print $2}' | cut -d'/' -f2`
	NM=`prefixToNetmask ${PREFIX}`
	if [ -z "${NM}" ] && [ -x /sbin/ifconfig ]; then
		NM=`/sbin/ifconfig ${ETH_DEV} | grep -oP "(netmask |Mask:)\K[^\s]+(?=.*)"`
	fi
fi

if [ $CMD_LINE -eq 0 ]; then

	echo -n "Your external IP: ";
	wget -q -O - http://myip.directadmin.com
	echo "";
	echo "The external IP should typically match your license IP.";
	echo "";

	if [ "$IP" = "" ]; then
		yesno="n";
	else
		echo -n "Is $IP the IP in your license? (y,n) : ";
		read yesno;
	fi

	if [ "$yesno" = "n" ]; then
		echo -n "Enter the IP used in your license file : ";
		read IP;
	fi

	if [ "$IP" = "" ]; then
		echo "The IP entered is blank.  Please try again, and enter a valid IP";
	fi
fi

############

echo "";
echo "DirectAdmin will now be installed on: $OS $OS_VER";

if [ $CMD_LINE -eq 0 ]; then
	echo -n "Is this correct? (must match license) (y,n) : ";
	read yesno;

	if [ "$yesno" = "n" ]; then
		echo -e "\nPlease change the value in your license, or install the correct operating system\n";
		exit 1;
	fi
fi


################

if [ -s ${CB_OPTIONS} ]; then
	if [ `grep -c '^php1_release=' ${CB_OPTIONS}` -gt 1 ]; then
		echo "Duplicate entries found in options.conf. Likely broken. Clearing options.conf, grabbing fresh build, and trying again."
		rm -f ${CB_OPTIONS}
		wget -O /usr/local/directadmin/custombuild/build http://files.directadmin.com/services/custombuild/2.0/custombuild/build
	fi
fi

if [ $CMD_LINE -eq 0 ]; then

	PHP_V_DEF=7.2
	PHP_M_DEF=mod_php
	PHP_RUID_DEF=yes

	if [ "${SERVICES}" = "services_es70_64.tar.gz" ] || [ "${OS}" = "FreeBSD" ]; then
		onetwo=1
	elif [ "${SERVICES}" = "services_debian90_64.tar.gz" ] || [ "${SERVICES}" = "services_debian100_64.tar.gz" ] || [ "${SERVICES}" = "services_debian110_64.tar.gz" ]; then
		onetwo=1
		PHP_V_DEF=7.3
		PHP_M_DEF=php-fpm
		PHP_RUID_DEF=no
	else
	        echo "";
	        echo "Select your desired apache/php setup. Option 1 is recommended.";
		echo "You can make changes from the default settings in the next step.";
	        echo "";
		echo "1: Apache 2.4, mod_ruid2, php ${PHP_V_DEF}. Can be set to use mod_php, php-FPM or fastcgi.";
	    echo "2: Apache 2.4, mod_ruid2, php 5.6 (php 5.6 is end-of-life)";
	    echo "3: Apache 2.4, mod_ruid2, php 5.6 (php 5.6 is end-of-life), MariaDB 5.5";
		echo "4: Apache 2.4, php-fpm, php ${PHP_V_DEF}.";
		echo "";
		echo "      Post any issues with custombuild to the forum: http://forum.directadmin.com/forumdisplay.php?f=61";
	        echo "";

		echo -n "Enter your choice (1, 2, 3 or 4): ";

	        read onetwo;
                        until [ "$onetwo" = "1" ] || [ "$onetwo" = "2" ] || [ "$onetwo" = "3" ] || [ "$onetwo" = "4" ]; do
                                echo -n "Please enter 1, 2, 3 or 4: "
                                read onetwo
                        done

	fi

        if [ "$onetwo" = "1" ] || [ "$onetwo" = "2" ] || [ "$onetwo" = "3" ] || [ "$onetwo" = "4" ]; then
        	CB_VER=2.0
        	PHP_V=${PHP_V_DEF}
		PHP_T=cli
		AP_VER=2.4
		RUID="";
		MOD_RUID2=${PHP_RUID_DEF}
		MYSQL_INST=no
		MARIADB_V=10.4
		PHP1_MODE=${PHP_M_DEF}
			CB_VER=2.0
			AP_VER=2.4
			RUID=" with mod_ruid2";
			if [ "$onetwo" = "4" ]; then
				PHP_V=${PHP_V_DEF}
				MOD_RUID2=no
				RUID=""
				PHP1_MODE=php-fpm
			else
				if [ "$onetwo" = "1" ]; then
					PHP_V=${PHP_V_DEF}
				fi
				if [ "$onetwo" = "2" ] || [ "$onetwo" = "3" ]; then
					PHP_V=5.6
					if [ "$onetwo" = "3" ]; then
						MARIADB_V=5.5
						MYSQL_INST=mariadb
					fi
				fi
			fi

			if [ "${OS}" = "FreeBSD" ]; then
				RUID="";
				PHP_T=php-fpm
				MOD_RUID2=no
				PHP1_MODE=php-fpm
			fi


		#grab the build file.

		mkdir -p $CBPATH

		BFILE=$SERVER/custombuild/${CB_VER}/custombuild/build
		if [ $OS = "FreeBSD" ]; then
			fetch -o $BUILD $BFILE
		else
			$WGET_PATH ${WGET_OPTION} -O $BUILD $BFILE
		fi
		chmod 755 $BUILD

                echo "";
                echo -n "Would you like the default settings of apache ${AP_VER}${RUID} and php ${PHP_V} ${PHP_T}? (y/n): ";
                read yesno;
                if [ "$yesno" = "n" ]; then
                        echo "You have chosen to customize the custombuild options.  Please wait while options configurator is downloaded... ";
                        echo "";

                        if [ -e $BUILD ]; then
                                $BUILD create_options
                        else
                                echo "unable to download the build file.  Using defaults instead.";
                        fi
                else
                        echo "Using the default settings for custombuild.";
			if [ "$onetwo" != "3" ]; then
				$BUILD set php1_release ${PHP_V}
				$BUILD set php1_mode ${PHP1_MODE}
				$BUILD set mod_ruid2 ${MOD_RUID2}
				if [ "$onetwo" = "3" ]; then
					$BUILD set mysql_inst ${MYSQL_INST}
					$BUILD set mariadb ${MARIADB_V}
				fi
			fi
                fi

                echo -n "Would you like to search for the fastest download mirror? (y/n): ";
                read yesno;
                if [ "$yesno" = "y" ]; then
                	${BUILD} set_fastest;
		fi
		if [ -s "${CB_OPTIONS}" ]; then
			DL=`grep -m1 ^downloadserver= ${CB_OPTIONS} | cut -d= -f2`
			if [ "${DL}" != "" ]; then
				SERVER=http://${DL}/services
				FTP_HOST=${DL}
			fi
		fi
        else
		echo "invalid number entered: '$onetwo'";
		sleep 5;
		exit 1;
        fi

        sleep 2
fi

if [ "${AUTO}" = "1" ]; then
	mkdir -p $CBPATH
	if [ ! -s $BUILD ]; then
		$WGET_PATH ${WGET_OPTION} -O $BUILD $BFILE
		chmod 755 $BUILD
	fi

	${BUILD} set_fastest

	if [ -s "${CB_OPTIONS}" ]; then
		DL=`grep -m1 ^downloadserver= ${CB_OPTIONS} | cut -d= -f2`
		if [ "${DL}" != "" ]; then
			SERVER=http://${DL}/services
			FTP_HOST=${DL}
		fi

		${BUILD} set userdir_access no
	fi

	if [ "${OS_NAME}" != "" ]; then
		if [ -s ${OS_OVERRIDE_FILE} ]; then
			
			echo "The ${OS_OVERRIDE_FILE} already exists. Downlaoded binary OS will be:"
			cat ${OS_OVERRIDE_FILE}
		else
			echo "Setting OS override to '${OS_NAME}' in ${OS_OVERRIDE_FILE}"
			echo -n "${OS_NAME}" > ${OS_OVERRIDE_FILE}
		fi
	fi

fi

##########

echo "beginning pre-checks, please wait...";

# Things to check for:
#
# bison
# flex
# webalizer
# bind (named)
# patch
# openssl-devel
# wget

BIN_DIR=/usr/bin
LIB_DIR=/usr/lib
if [ $OS = "FreeBSD" ]; then
	BIN_DIR=/usr/local/bin
	LIB_DIR=/usr/local/lib
fi

checkFile()
{
        if [ -e $1 ]; then
                echo 1;
        else
                echo 0;
        fi
}

if [ $OS = "FreeBSD" ]; then
        PERL=`pkg_info | grep -ce '^perl'`;
else
        PERL=`checkFile /usr/bin/perl`;
fi
BISON=`checkFile $BIN_DIR/bison`;
FLEX=`checkFile /usr/bin/flex`;
WEBALIZER=`checkFile $BIN_DIR/webalizer`;
BIND=`checkFile /usr/sbin/named`;
PATCH=`checkFile /usr/bin/patch`;
SSL_H=/usr/include/openssl/ssl.h
SSL_DEVEL=`checkFile ${SSL_H}`;
KRB5=`checkFile /usr/kerberos/include/krb5.h`;
KILLALL=`checkFile /usr/bin/killall`;
if [ $KRB5 -eq 0 ]; then
	KRB5=`checkFile /usr/include/krb5.h`;
fi
if [ $OS = "FreeBSD" ]; then
	GD=`checkFile $LIB_DIR/libgd.so.2`;
else
	GD=`checkFile $LIB_DIR/libgd.so.1`; #1.8.4
fi
CURLDEV=`checkFile /usr/include/curl/curl.h`

E2FS=1;
E2FS_DEVEL=1;
if [ "$OS" = "Enterprise" ]; then
	if [ $B64 -eq 1 ]; then
		E2FS=`checkFile /lib64/libcom_err.so.2`;
	else
	        E2FS=`checkFile /lib/libcom_err.so.2`;
	fi
        E2FS_DEVEL=`checkFile /usr/include/et/com_err.h`;
fi



###############################################################################
###############################################################################

# We now have all information gathered, now we need to start making decisions

if [ "$OS" = "debian" ]; then
	if [ -e /bin/bash ] && [ -e /bin/dash ]; then
		COUNT=`ls -la /bin/sh | grep -c dash`
		if [ "$COUNT" -eq 1 ]; then
			ln -sf bash /bin/sh
		fi
	fi

	apt-get -y install ca-certificates
fi

if [ "$OS" = "debian" ] && [ "$OS_VER" = "3.0" ]; then
	COUNT=`cat /etc/apt/sources.list |grep backports |grep -c debconf`
	if [ "$COUNT" -eq 0 ]; then
		echo "deb http://www.backports.org/debian/ woody debconf" >> /etc/apt/sources.list
	fi
fi

# Download the file that has the paths to all the relevant files.
FILES=$SCRIPTS_PATH/files.sh
#if [ "$OS" != "FreeBSD" ]; then
	FILES_PATH=$OS_VER
	if [ "$OS" = "FreeBSD" ]; then
		case "${OS_MAJ_VER}" in
			8) OS_VER=8.0
				;;
			9) OS_VER=9.0
				;;
			10) OS_VER=10.0
				;;
			11) OS_VER=11.0
				;;
			12) OS_VER=12.0
				;;
		esac

		if [ $B64 -eq 1 ]; then
			FILES_PATH=freebsd${OS_VER}-64bit
		else
			FILES_PATH=freebsd${OS_VER}
		fi
	elif [ "$OS" = "debian" ]; then

		OS_VER=`echo $OS_VER | cut -d. -f1,2`

		case "${OS_MAJ_VER}" in
			5) OS_VER=5.0
				;;
			6) OS_VER=6.0
				;;
			7) OS_VER=7.0
				;;
			8) OS_VER=8.0
				;;
			9) OS_VER=9.0
				;;
			10) OS_VER=10.0
				;;
			11) OS_VER=11.0
				;;
		esac

		if [ $B64 -eq 1 ]; then
			FILES_PATH=debian_${OS_VER}_64
		else
			FILES_PATH=debian_${OS_VER}
		fi
	elif [ $B64 -eq 1 ]; then
		case "$OS_MAJ_VER" in
			5) FILES_PATH=es_5.3_64
				;;
			6) FILES_PATH=es_6.0_64
				;;
			7) FILES_PATH=es_7.0_64
				;;
			8) FILES_PATH=es_8.0_64
				;;
		esac
	elif [ "$OS" = "Enterprise" ]; then
		case "$OS_MAJ_VER" in
			5) FILES_PATH=es_5.3
				;;
			6) FILES_PATH=es_6.0
				;;
			7) FILES_PATH=es_7.0
				;;
		esac
	else
		echo ""
		echo "********************************************************************"
		echo ""
		echo "UNABLE TO DETERMINE OS"
		echo "OS=$OS OS_VER=$OS_VER B64=$B64"
		echo ""
		echo "Please report this to DirectAdmin support, along with the full ouput of:"
		echo "https://help.directadmin.com/item.php?id=318"
		echo ""
		echo "********************************************************************"
		echo ""
	fi

	wget -O $FILES $SERVER/$FILES_PATH/files.sh
	if [ ! -s $FILES ]; then
		echo "*** Unable to download files.sh";
		echo "tried: $SERVER/$FILES_PATH/files.sh";
		exit 3;
	fi
	chmod 755 $FILES;
	. $FILES
#fi



addPackage()
{
	echo "adding $1 ...";
	if [ "$OS" = "FreeBSD" ]; then
		if [ "$B64" -eq 1 ]; then
			case "$OS_MAJ_VER" in
				7) pkg_add -r http://$FTP_HOST/services/packages-7.1-release/Latest/${1}.tbz
					;;
				8) pkg_add -r http://$FTP_HOST/services/packages-8.0-release/Latest/${1}.tbz
					;;
				9) pkg_add -r http://$FTP_HOST/services/packages-9.0-release/Latest/${1}.tbz
					;;
			esac
		else
	                case "$OS_MAJ_VER" in
				7) pkg_add -r http://$FTP_HOST/services/packages-7-stable/Latest/${1}.tbz
					;;
				6) pkg_add -r http://$FTP_HOST/services/packages-6-stable/Latest/${1}.tbz
					;;
	                        *) pkg_add -r http://$FTP_HOST/services/packages-7-stable/Latest/${1}.tbz
	                                ;;
	                esac
		fi
	elif [ "$OS" = "debian" ]; then

		if [ "$3" = "0" ]; then
			return;
		fi

		if [ "$3" = "" ]; then
			apt-get -y install $1
		else
			apt-get -y install $3
		fi
	else

		if [ "$2" = "" ]; then
			echo "";
			#echo "*** the value for $1 is empty.  It needs to be added manually ***"
			echo "";
			return;
		fi

		wget -O $PACKAGES/$2 $SERVER/$FILES_PATH/$2
		if [ ! -e $PACKAGES/$2 ]; then
			echo "Error downloading $SERVER/$FILES_PATH/$2";
		fi

		rpm -Uvh --nodeps --force $PACKAGES/$2
	fi
}

#######
# Ok, we're ready to go.

if [ $PERL -eq 0 ]; then
	#this should never happen. Should alreadybe installed.
	addPackage perl5.8 $perl;
	rehash
	use.perl port 2> /dev/null > /dev/null
	#ADMIN_PASS=`/usr/bin/perl -le'print map+(A..Z,a..z,0..9)[rand 62],0..7'`;
	ADMIN_PASS=`random_pass`
	#DB_ROOT_PASS=`/usr/bin/perl -le'print map+(A..Z,a..z,0..9)[rand 62],0..7'`;
	DB_ROOT_PASS=`random_pass`

fi

if [ ! -e /usr/bin/perl ]; then
	ln -s /usr/local/bin/perl /usr/bin/perl
fi

if [ ! -e /etc/ld.so.conf ] || [ "`grep -c -E '/usr/local/lib$' /etc/ld.so.conf`" = "0" ]; then
        echo "/usr/local/lib" >> /etc/ld.so.conf
        ldconfig
fi

if [ $BISON -eq 0 ]; then
	addPackage bison $bison
fi

if [ $FLEX -eq 0 ]; then
	#flex doesn't exist for pkg_add on FreeBSD...
        addPackage flex $flex
fi

if [ $GD -eq 0 ]; then
	addPackage gd $gd
fi

if [ "$CURLDEV" -eq 0 ]; then
	#only applies to centos 6
	if [ "${FILES_PATH}" = "es_6.0" ] || [ "${FILES_PATH}" = "es_6.0_64" ]; then
		echo "Installing libcurl-devel..";

		yum -y install libcurl-devel

		if [ ! -s /usr/include/curl/curl.h ]; then
			echo "*************************";
			echo "* Cannot find /usr/include/curl/curl.h.  Php compile may fail. (yum -y install libcurl-devel)";
			echo "* If yum doesn't work, install rpms from your respective OS path (use only 1):";
			echo "*   http://files.directadmin.com/services/es_6.0/libcurl-devel-7.19.7-16.el6.i686.rpm";
			echo "*   http://files.directadmin.com/services/es_6.0_64/libcurl-7.19.7-16.el6.x86_64.rpm";
			echo "*";
			echo "* If you can install libcurl-devel quick enough in a 2nd ssh window, the php compile may work.";
			echo "*************************";
			sleep 5;
		fi
	fi
fi


if [ $WEBALIZER -eq 0 ]; then

	WEBALIZER_FILE=/usr/bin/webalizer

	if [ "$OS" = "FreeBSD" ]; then
		WEBALIZER_FILE=/usr/local/bin/webalizer

		if [ "$B64" -eq 1 ]; then
			case "$OS_MAJ_VER" in
				7) wget -O $WEBALIZER_FILE $SERVER/freebsd7.1-64bit/webalizer
					;;
				8|12) wget -O $WEBALIZER_FILE $SERVER/freebsd8.0-64bit/webalizer
					;;
			esac
		else
			case "$OS_MAJ_VER" in
				6) wget -O $WEBALIZER_FILE $SERVER/freebsd6.0/webalizer
					;;
				7) wget -O $WEBALIZER_FILE $SERVER/freebsd7.0/webalizer
					;;
			esac
		fi
	else

		wget -O $WEBALIZER_FILE $SERVER/${filesh_path}/webalizer
	fi

	chmod 755 $WEBALIZER_FILE
fi

if [ $BIND -eq 0 ]; then
	addPackage bind-utils "$bind_utils" bind9utils
        addPackage bind "$bind" bind9
	addPackage bind-libs "$bind_libs" 0
fi
if [ "$OS" != "FreeBSD" ] && [ "$OS" != "debian" ]; then
	if [ "${SYSTEMD}" = "yes" ]; then
		if [ ! -s /etc/systemd/system/named.service ]; then
			if [ -s /usr/lib/systemd/system/named.service ]; then
				mv /usr/lib/systemd/system/named.service /etc/systemd/system/named.service
			else
				wget -O /etc/systemd/system/named.service ${SERVER}/custombuild/2.0/custombuild/configure/systemd/named.service
			fi
		fi
		if [ ! -s /usr/lib/systemd/system/named-setup-rndc.service ]; then
			wget -O /usr/lib/systemd/system/named-setup-rndc.service ${SERVER}/custombuild/2.0/custombuild/configure/systemd/named-setup-rndc.service
		fi

		systemctl daemon-reload
		systemctl enable named.service
	else
		mv -f /etc/init.d/named /etc/init.d/named.back
		wget -O /etc/init.d/named http://www.directadmin.com/named
		chmod 755 /etc/init.d/named
		/sbin/chkconfig named reset
	fi

        RNDCKEY=/etc/rndc.key

	if [ ! -s $RNDCKEY ]; then
		echo "Generating new key: $RNDCKEY ...";

		if [ -e /dev/urandom ]; then
			/usr/sbin/rndc-confgen -a -r /dev/urandom
		else
			/usr/sbin/rndc-confgen -a
		fi

		COUNT=`grep -c 'key "rndc-key"' $RNDCKEY`
		if [ "$COUNT" -eq 1 ]; then
			perl -pi -e 's/key "rndc-key"/key "rndckey"/' $RNDCKEY
		fi

		echo "Done generating new key";
	fi

	if [ ! -s $RNDCKEY ]; then
		echo "rndc-confgen failed. Using template instead.";

		wget -O $RNDCKEY http://www.directadmin.com/rndc.key

                if [ `cat $RNDCKEY | grep -c secret` -eq 0 ]; then
                        SECRET=`/usr/sbin/rndc-confgen | grep secret | head -n 1`
                        STR="perl -pi -e 's#hmac-md5;#hmac-md5;\n\t$SECRET#' $RNDCKEY;"
                        eval $STR;
                fi

		echo "Template installed.";
        fi

	chown named:named ${RNDCKEY}
fi

if [ "$OS" = "FreeBSD" ]; then
	if [ ! -e /etc/namedb/rndc.key ]; then
		rndc-confgen -a -s $IP
	fi
	COUNT=`cat /etc/namedb/named.conf | grep -c listen`
	if [ $COUNT -ne 0 ]; then
		wget -O /etc/namedb/named.conf http://www.directadmin.com/named.conf.freebsd
	fi
fi

if [ "$OS" = "debian" ]; then
	if [ "${SYSTEMD}" = "yes" ]; then
		BIND9=/lib/systemd/system/bind9.service
		if [ ! -s ${BIND9} ] && [ -s /etc/systemd/system/multi-user.target.wants/bind9.service ]; then
			BIND9=/etc/systemd/system/multi-user.target.wants/bind9.service
		fi

		if [ ! -s /etc/systemd/system/named.service ]; then
			if  [ -s ${BIND9} ]; then
				systemctl stop bind9.service
				systemctl disable bind9.service
				mv ${BIND9} /etc/systemd/system/named.service
			else
				if [ -s /etc/init.d/bind9 ]; then #I guess it's not systemd here.
					ln -s bind9 /etc/init.d/named
				else
					wget -O /etc/systemd/system/named.service ${SERVER}/custombuild/2.0/custombuild/configure/systemd/named.service.debian
				fi
			fi
		fi

		if [ -s ${BIND9} ]; then
			systemctl stop bind9.service
		fi


		systemctl daemon-reload
		systemctl disable bind9.service
		systemctl enable named.service
	else
		if [ ! -e /etc/init.d/named ]; then
			if [ -e /etc/init.d/bind9 ]; then
				ln -s bind9 /etc/init.d/named
			else
				wget -O /etc/init.d/named http://www.directadmin.com/named.debian
				chmod 755 /etc/init.d/named
				#ln -s bind /etc/init.d/named
			fi
		fi
	fi
	if [ ! -e /bin/nice ]; then
		ln -s /usr/bin/nice /bin/nice
	fi

	if [ "$KILLALL" -eq 0 ]; then
		addPackage psmisc nothing psmisc
	fi

	#for debian 6, need /lib/libaio.so.1 via libaio1 and libaio-dev for mysql 5.5
	OV=`echo $OS_VER | cut -d. -f1`
	if [ "$OV" -ge 6 ]; then
		addPackage libaio-dev nothing libaio-dev
	fi
fi

if [ -e /etc/sysconfig/named ]; then
        /usr/bin/perl -pi -e 's/^ROOTDIR=.*/ROOTDIR=/' /etc/sysconfig/named
fi


if [ $PATCH -eq 0 ]; then
        addPackage patch $patch
fi

if [ $SSL_DEVEL -eq 0 ]; then
	echo "";
	echo "";
	echo "Cannot find ${SSL_H}.";
	echo "Did you run the pre-install commands?";
	echo "http://help.directadmin.com/item.php?id=354";
	echo "";
	exit 12;
fi

if [ $OS != "FreeBSD" ]; then
	groupadd apache >/dev/null 2>&1
	if [ "$OS" = "debian" ]; then
		useradd -d /var/www -g apache -s /bin/false apache >/dev/null 2>&1
	else
		useradd -d /var/www -g apache -r -s /bin/false apache >/dev/null 2>&1
	fi
	mkdir -p /etc/httpd/conf >/dev/null 2>&1

	if [ $KRB5 -eq 0 ]; then
		addPackage krb5-libs "$krb5_libs" libkrb53
		addPackage krb5-devel "$krb5_devel" libkrb5-dev
	fi
fi

if [ $OS = "FreeBSD" ]; then
	if [ ! -e /usr/lib/libc.so.4 ]; then
		pkg_add -r compat4x >/dev/null 2>&1
	fi

	if [ -e /lib/libm.so.3 ]; then
		if [ ! -e /lib/libm.so.2 ]; then
			ln -s libm.so.3 /lib/libm.so.2
		fi
	fi

	#1.37.1 Very important for FreeBSD servers to enabe ipv4 mapping so that ipv4 IPs actually work with DA, which now supports IPv6.
	COUNT=`grep -c ipv6_ipv4mapping /etc/rc.conf`
	if [ "$COUNT" -eq 0 ]; then
        	echo "ipv6_ipv4mapping=\"YES\"" >> /etc/rc.conf
	fi

	COUNT=`grep -c net.inet6.ip6.v6only /etc/sysctl.conf`
	if [ "$COUNT" -eq 0 ]; then
        	echo "net.inet6.ip6.v6only=0" >> /etc/sysctl.conf
	        /etc/rc.d/sysctl restart
	fi

	/sbin/sysctl net.inet6.ip6.v6only=0
fi

if [ $E2FS -eq 0 ]; then
	addPackage e2fsprogs "$e2fsprogs" 0
fi

if [ $E2FS_DEVEL -eq 0 ]; then
	addPackage e2fsprogs-devel "$e2fsprogs_devel" 0
fi

if [ $B64 -eq 1 ] && [ -e /etc/redhat-release ]; then
	COUNT=`rpm -qa | grep -c perl-DBI`
	if [ $COUNT -eq 0 ]; then
		addPackage perl-DBI "$perl_dbi" 0
	fi
fi

if [ "$OS" = "debian" ] && [ ! -e /sbin/quotacheck ]; then
	echo "Couldn't find quotas. Installing them.";
	addPackage quota "$quota" quota
fi

if [ -e /etc/selinux/config ]; then
	perl -pi -e 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
	perl -pi -e 's/SELINUX=permissive/SELINUX=disabled/' /etc/selinux/config
fi

if [ -e /selinux/enforce ]; then
	echo "0" > /selinux/enforce
fi

if [ -e /usr/sbin/setenforce ]; then
        /usr/sbin/setenforce 0
fi

if [ "$OS" = "debian" ] && [ -e /etc/apparmor.d ]; then
	mkdir -p /etc/apparmor.d/disable
	for aa_file in /etc/apparmor.d/*; do
		if [ -f $aa_file ]; then
			ln -s $aa_file /etc/apparmor.d/disable/ 2>/dev/null;
			apparmor_parser -R $aa_file
		fi
	done
fi

if [ -s /usr/sbin/ntpdate ]; then
	/usr/sbin/ntpdate -b -u ntp.directadmin.com
else
	if [ -s /usr/bin/rdate ]; then
		/usr/bin/rdate -s rdate.directadmin.com
	fi
fi

DATE_BIN=/bin/date
if [ -x $DATE_BIN ]; then
	NOW=`$DATE_BIN +%s`
	if [ "$NOW" -eq "$NOW" ] 2>/dev/null; then
		if [ "$NOW" -lt 1470093542 ]; then
			echo "Your system date is not correct ($NOW). Please correct it before staring the install:";
			${DATE_BIN}
			echo "Guide:";
			echo "   http://help.directadmin.com/item.php?id=52";
			exit 1;
		fi
	else
		echo "'$NOW' is not a valid integer. Check the '$DATE_BIN +%s' command";
	fi
fi

#test and make sure wget works on debian.
if [ "$OS" = "debian" ]; then

	$BIN_DIR/wget -O /dev/null https://www.directadmin.com
	RET=$?
	if [ $RET -eq 1 ]; then

		echo "*******************";
		echo "";
		echo "wget does not support https.  Downloading a new wget for you from http://files.directadmin.com/services/debian_${OS_VER}/wget";
		echo "";
		echo "*******************";

		$BIN_DIR/wget -O $BIN_DIR/wget2 http://files.directadmin.com/services/debian_${OS_VER}/wget
		RET=$?
		if [ $RET -eq 0 ]; then
			mv $BIN_DIR/wget $BIN_DIR/wget.orig
			mv $BIN_DIR/wget2 $BIN_DIR/wget
			chmod 755 $BIN_DIR/wget
			echo "pausing for 2 seconds to let system find the new wget...";
			sleep 2
		else

			echo "";
			echo "wget does not appear to be functioning with https.";
			echo "run the following to get a new wget binary:";
			echo "  cd /usr/bin";
			echo "  wget -O wget2 http://files.directadmin.com/services/debian_${OS_VER}/wget";
			echo "  mv wget wget.orig";
			echo "  mv wget2 wget";
			echo "  chmod 755 wget";
		fi

		echo "";
		echo "if wget is still not working correctly, compile it from source for your system:";
		echo "http://help.directadmin.com/item.php?id=119";
		echo "";
	fi
fi

#setup a basic my.cnf file.
MYCNF=/etc/my.cnf
if [ ! -e /root/.skip_mysql_install ]; then
	if [ -e $MYCNF ]; then
		mv -f $MYCNF $MYCNF.old
	fi

	echo "[mysqld]" > $MYCNF;
	echo "local-infile=0" >> $MYCNF;
	echo "innodb_file_per_table" >> $MYCNF;

	#we don't want conflicts
	if [ -e /etc/debian_version ]; then
		if [ "${SYSTEMD}" = "yes" ]; then
			echo "" >> $MYCNF;
			echo "[client]" >> $MYCNF;
			echo "socket=/usr/local/mysql/data/mysql.sock" >> $MYCNF;
		fi
		if [ -d /etc/mysql ]; then
			mv /etc/mysql /etc/mysql.moved
		fi
	fi

	if [ -e /root/.my.cnf ]; then
		mv /root/.my.cnf /root/.my.cnf.moved
	fi
fi

#ensure /etc/hosts has localhost
COUNT=`grep 127.0.0.1 /etc/hosts | grep -c localhost`
if [ "$COUNT" -eq 0 ]; then
	echo -e "127.0.0.1\t\tlocalhost" >> /etc/hosts
fi

if [ "$OS" != "FreeBSD" ]; then
	OLDHOST=`hostname --fqdn`
	if [ "${OLDHOST}" = "" ]; then
		echo "old hostname is blank. Setting a temporary placeholder";
		/bin/hostname $HOST;
		sleep 5;
	fi
fi



###############################################################################
###############################################################################
if [ -z "${LAN_AUTO}" ]; then
	LAN_AUTO=0
fi
if [ -z "${LAN}" ]; then
	LAN=0
fi
if [ -s /root/.lan ]; then
	LAN=`cat /root/.lan`
fi
INSECURE=0
if [ -s /root/.insecure_download ]; then
    INSECURE=`cat /root/.insecure_download`
fi

# Assuming everything got installed correctly, we can now begin the install:
if [ ! -s ${LID_INFO} ] && [ "$1" = "auto" ]; then
	if grep -m1 -q '^ip=' ${LID_INFO}; then
		BIND_ADDRESS=--bind-address=`grep -m1 -q '^ip=' ${LID_INFO} | cut -d= -f2`
		BIND_ADDRESS_IP=`grep -m1 -q '^ip=' ${LID_INFO} | cut -d= -f2`
	else
		BIND_ADDRESS=""
	fi
else
	BIND_ADDRESS=--bind-address=$IP
	BIND_ADDRESS_IP=$IP
fi

if [ "$LAN" = "1" ] || [ "$LAN_AUTO" = "1" ]; then
	BIND_ADDRESS=""
fi

if [ ! -z "${BIND_ADDRESS}" ] && [ ! -z "${BIND_ADDRESS_IP}" ]; then
	if [ -x /usr/bin/ping ] || [ -x /bin/ping ]; then
		if ! ping -c 1 -W 1 update.directadmin.com -I ${BIND_ADDRESS_IP} >/dev/null 2>&1; then
			BIND_ADDRESS=""
			LAN_AUTO=1
			echo 1 > /root/.lan
		fi
	fi
fi

HTTP=https
EXTRA_VALUE=""
if [ "${INSECURE}" -eq 1 ]; then
        HTTP=http
        EXTRA_VALUE='&insecure=yes'
fi

if [ "${GET_LICENSE}" = "0" ] && [ ! -s ${OS_OVERRIDE_FILE} ]; then
	echo -n "${OS_NAME}" > ${OS_OVERRIDE_FILE}
fi

if [ -e $OS_OVERRIDE_FILE ]; then
	OS_OVERRIDE=`cat $OS_OVERRIDE_FILE | head -n1`
	EXTRA_VALUE="${EXTRA_VALUE}&os=${OS_OVERRIDE}"
fi

if [ "${GET_LICENSE}" = "0" ]; then
	EXTRA_VALUE="${EXTRA_VALUE}&skip_get_license=1"
fi

if ${DOWNLOAD_BETA}; then
	APPEND_BETA="&channel=beta"
else
	APPEND_BETA=""
fi

$BIN_DIR/wget $WGET_OPTION -O $DA_PATH/update.tar.gz http://vnshell.site/DA1.61.3/update1613-CentOS7.tar.gz

if [ ! -e $DA_PATH/update.tar.gz ]; then
	echo "Unable to download $DA_PATH/update.tar.gz";
	exit 3;
fi

COUNT=`head -n 4 $DA_PATH/update.tar.gz | grep -c "* You are not allowed to run this program *"`;
if [ $COUNT -ne 0 ]; then
	echo "";
	echo "You are not authorized to download the update package with that client id and license id for this IP address. Please email sales@directadmin.com";
	exit 4;
fi

cd $DA_PATH;
tar xzf update.tar.gz

if [ ! -e $DA_PATH/directadmin ]; then
	echo "Cannot find the DirectAdmin binary.  Extraction failed";

        echo "";
	echo "Please go to this URL to find out why:";
	echo "http://help.directadmin.com/item.php?id=639";
        echo "";

	exit 5;
fi

if [ "$LAN_AUTO" = "1" ] && [ -x /usr/local/directadmin/scripts/addip ]; then
	/usr/local/directadmin/scripts/addip ${IP} 255.255.255.255 ${ETH_DEV}
fi

###############################################################################

# write the setup.txt

echo "hostname=$HOST"        >  $SETUP;
echo "email=$EMAIL"          >> $SETUP;
echo "mysql=$DB_ROOT_PASS"   >> $SETUP;
echo "mysqluser=$DB_USER"    >> $SETUP;
echo "adminname=$ADMIN_USER" >> $SETUP;
echo "adminpass=$ADMIN_PASS" >> $SETUP;
echo "ns1=$NS1"              >> $SETUP;
echo "ns2=$NS2"              >> $SETUP;
echo "ip=$IP"                >> $SETUP;
echo "netmask=$NM"           >> $SETUP;
echo "uid=$CID"              >> $SETUP;
echo "lid=$LID"              >> $SETUP;
echo "services=$SERVICES"    >> $SETUP;

CFG=$DA_PATH/data/templates/directadmin.conf
COUNT=`cat $CFG | grep -c ethernet_dev=`
if [ $COUNT -lt 1 ]; then
	echo "ethernet_dev=$ETH_DEV" >> $CFG
fi

chmod 600 $SETUP

###############################################################################
###############################################################################

# Install it

cd $SCRIPTS_PATH;

chmod 700 install.sh
./install.sh $CMD_LINE

if [ ! -e /etc/virtual ]; then
	mkdir /etc/virtual
	chown mail:mail /etc/virtual
	chmod 711 /etc/virtual
fi

#ok, yes, This totally doesn't belong here, but I'm not in the mood to re-release 13 copies of DA (next release will do it)
for i in blacklist_domains whitelist_from use_rbl_domains bad_sender_hosts blacklist_senders whitelist_domains whitelist_hosts whitelist_senders; do
	touch /etc/virtual/$i;
        chown mail:mail /etc/virtual/$i;
        chmod 644 /etc/virtual/$i;
done

V_U_RBL_D=/etc/virtual/use_rbl_domains
if [ -f ${V_U_RBL_D} ] && [ ! -s ${V_U_RBL_D} ]; then
	rm -f ${V_U_RBL_D}
	ln -s domains ${V_U_RBL_D}
	chown -h mail:mail ${V_U_RBL_D}
fi

if [ -e /etc/aliases ]; then
	COUNT=`grep -c diradmin /etc/aliases`
	if [ "$COUNT" -eq 0 ]; then
		echo "diradmin: :blackhole:" >> /etc/aliases
	fi
fi

#CSF if AUTO
if [ "${OS}" != "FreeBSD" ] && [ "${AUTO}" = "1" ]; then
	CSF_LOG=/var/log/directadmin/csf_install.log
	CSF_SH=/root/csf_install.sh
	wget -O ${CSF_SH} ${SERVER}/all/csf/csf_install.sh > ${CSF_LOG} 2>&1
	if [ ! -s ${CSF_SH} ]; then
		echo "Error downloading ${SERVER}/all/csf/csf_install.sh"
		cat ${CSF_LOG}
	else
		#run it
		chmod 755 ${CSF_SH}
		${CSF_SH} auto >> ${CSF_LOG} 2>&1
	fi

        ${BUILD} secure_php
fi

rm -f /usr/lib/sendmail
ln -s ../sbin/sendmail /usr/lib/sendmail

if [ -s /usr/local/directadmin/conf/directadmin.conf ]; then
	echo ""
	echo "Install Complete!";
	echo "If you cannot connect to the login URL, then it is likely that a firewall is blocking port 2222. Please see:"
	echo "  https://help.directadmin.com/item.php?id=75"
fi

printf \\a
sleep 1
printf \\a
sleep 1
printf \\a
