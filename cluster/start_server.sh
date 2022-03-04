#!/bin/sh
#
# -*- coding: utf-8 -*-
#
# K2hdkc Python Driver under MIT License
#
# Copyright (c) 2022 Yahoo Japan Corporation
#
# For the full copyright and license information, please view
# the license file that was distributed with this source code.
#
# AUTHOR:   Hirotaka Wakabayashi
# CREATE:   Tue Feb 08 2022
# REVISION:
#

# Sets PATH. setup_*.sh uses useradd command
PATH=${PATH}:/usr/sbin:/sbin

# an unset parameter expansion will fail
set -u

# umask 022 is enough
umask 022

# environments
SRCDIR=$(cd $(dirname "$0") && pwd)
DEBUG=1
if test "${DEBUG}" -eq 1; then
	TAG="$(basename $0) -s"
else
	TAG=$(basename $0)
fi
USER=$(whoami)
LOGLEVEL=info

# Starts chmpx and k2hdkc
#
start_process() {
	echo "chmpx -conf ${SRCDIR}/server.yaml -d ${LOGLEVEL} > ${SRCDIR}/chmpx.log 2>&1"
	nohup chmpx -conf ${SRCDIR}/server.yaml -d ${LOGLEVEL} > ${SRCDIR}/chmpx.log 2>&1 &
	echo "sleep 3"
	sleep 3
	echo "k2hdkc -conf ${SRCDIR}/server.yaml -d ${LOGLEVEL} > ${SRCDIR}/k2hdkc.log 2>&1"
	nohup k2hdkc -conf ${SRCDIR}/server.yaml -d ${LOGLEVEL} > ${SRCDIR}/k2hdkc.log 2>&1 &
	echo "sleep 3"
	sleep 3
	echo "chmpx -conf ${SRCDIR}/slave.yaml -d ${LOGLEVEL}  > ${SRCDIR}/slave.log 2>&1"
	nohup chmpx -conf ${SRCDIR}/slave.yaml -d ${LOGLEVEL}  > ${SRCDIR}/slave.log 2>&1 &
	echo "sleep 3"
	sleep 3
}

# Stops chmpx and k2hdkc
#
stop_process() {
	for PROC in chmpx k2hdkc; do
		echo "pgrep -u ${USER} -x ${PROC}"
		pgrep -u ${USER} -x ${PROC}
		if test "${?}" = "0"; then
			echo "pkill -9 -x ${PROC}"
			pkill -9 -x ${PROC}
		fi
	done
}

# Shows status of chmpx and k2hdkc
#
status_process() {
	RET=0
	for PROC in chmpx k2hdkc; do
		echo "pgrep -u ${USER} -x ${PROC}"
		pgrep -u ${USER} -x ${PROC}
		RET=$(echo ${?} + ${RET}|bc)
	done
	return ${RET}
}

# Starts chmpx and k2hdkc if no chmpx and k2hdkc processes are running
#
startifnotexist() {
	status_process
	if test "${RET}" = "2" ; then
		echo "start_process"
		start_process
	elif test "${RET}" = "1" ; then
		echo "stop_process"
		stop_process
		echo "start_process"
		start_process
	fi
}

# Checks if k2hdkc is installed 
#
# Params::
#   no params
#
# Returns::
#   0 on installed
#   1 on not installed
#
which_k2hdkc() {
	which k2hdkc
	if test "${?}" = "0"; then
		echo "[OK] k2hdkc already installed"
		return 0
	fi
	return 1
}

# Determines the current OS
#
# Params::
#   no params
#
# Returns::
#   0 on success
#   1 on failure
#
setup_os_env() {
	if test -f "/etc/os-release"; then
		. /etc/os-release
		OS_NAME=$ID
		OS_VERSION=$VERSION_ID
	else
		echo "[OK] unknown OS, no /etc/os-release and /etc/centos-release falling back to CentOS-7"
		OS_NAME=centos
		OS_VERSION=7
	fi

	if test "${OS_NAME}" = "ubuntu"; then
		echo "[OK] ubuntu configurations are currently equal to debian one"
		OS_NAME=debian
	fi

	HOSTNAME=$(hostname)
	echo "[OK] HOSTNAME=${HOSTNAME} OS_NAME=${OS_NAME} OS_VERSION=${OS_VERSION}"
}

# Builds k2hash from source code
#
# Params::
#   $1 os_name
#
# Returns::
#   0 on success
#   1 on failure(exit)
#
make_k2hash() {

	_os_name=${1:?"os_name should be nonzero"}

	if test "${_os_name}" = "debian" -o "${_os_name}" = "ubuntu"; then
		_configure_opt="--with-gcrypt"
		sudo apt-get update -y
		sudo apt-get install -y git curl autoconf autotools-dev gcc g++ make gdb libtool pkg-config libyaml-dev libgcrypt20-dev
	elif test "${_os_name}" = "fedora"; then
		_configure_opt="--with-nss"
		sudo dnf install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig libyaml-devel nss-devel
	elif test "${_os_name}" = "centos" -o "${_os_name}" = "rhel"; then
		_configure_opt="--with-nss"
		if test "${OS_VERSION}" = "7"; then
		    sudo yum install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig libyaml-devel nss-devel
		elif test "${OS_VERSION}" = "8"; then
		    sudo dnf install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig
			sudo dnf install -y --enablerepo=powertools nss-devel libyaml-devel
		fi
	else
		echo "[NO] OS should be debian, ubuntu, fedora, centos or rhel"
		exit 1
	fi

	echo "[OK] git clone https://github.com/yahoojapan/fullock"
	git clone https://github.com/yahoojapan/fullock
	echo "[OK] git clone https://github.com/yahoojapan/k2hash"
	git clone https://github.com/yahoojapan/k2hash
	
	if ! test -d "fullock"; then
		echo "no fullock"
		exit 1
	fi
	cd fullock
	./autogen.sh
	./configure --prefix=/usr
	make
	sudo make install
	
	if ! test -d "../k2hash"; then
		echo "no k2hash"
		exit 1
	fi
	cd ../k2hash
	./autogen.sh
	./configure --prefix=/usr ${_configure_opt}
	make
	sudo make install
	
	return 0
}

# Builds k2hdkc from source code
#
# Params::
#   $1 os_name
#
# Returns::
#   0 on success
#   1 on failure(exit)
#
make_k2hdkc() {

	_os_name=${1:?"os_name should be nonzero"}

	make_k2hash ${_os_name}

	if test "${_os_name}" = "debian" -o "${_os_name}" = "ubuntu"; then
		_configure_opt="--with-gnutls"
		sudo apt-get update -y
		sudo apt-get install -y git curl autoconf autotools-dev gcc g++ make gdb libtool pkg-config libyaml-dev libgnutls28-dev
	elif test "${_os_name}" = "fedora"; then
		_configure_opt="--with-nss"
		sudo dnf install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig libyaml-devel nss-devel
	elif test "${_os_name}" = "centos" -o "${_os_name}" = "rhel"; then
		_configure_opt="--with-nss"
		if test "${OS_VERSION}" = "7"; then
		    sudo yum install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig libyaml-devel nss-devel
		elif test "${OS_VERSION}" = "8"; then
		    sudo dnf install -y git curl autoconf automake gcc gcc-c++ gdb make libtool pkgconfig
			sudo dnf install -y --enablerepo=powertools nss-devel libyaml-devel
		fi
	else
		echo "[NO] OS should be debian, ubuntu, fedora, centos or rhel"
		exit 1
	fi

	echo "[OK] git clone https://github.com/yahoojapan/k2hdkc"
	git clone https://github.com/yahoojapan/k2hdkc
	cd k2hdkc
	
	echo "[OK] git clone https://github.com/yahoojapan/chmpx"
	git clone https://github.com/yahoojapan/chmpx
	
	cd chmpx
	./autogen.sh
	./configure --prefix=/usr ${_configure_opt}
	make
	sudo make install
	
	cd ..
	./autogen.sh
	./configure --prefix=/usr ${_configure_opt}
	make
	sudo make install

	which k2hdkc
	if test "${?}" != "0"; then
		echo "[NO] no k2hdkc installed"
		exit 1
	fi
	return 0
}

#
# main loop
#

setup_os_env

which_k2hdkc
if test "${?}" = "0"; then
	startifnotexist
	exit 0
fi

if test "${OS_NAME}" = "fedora"; then
	which sudo
	if test "${?}" = "1"; then
		dnf install -y sudo
	fi
	which bc
	if test "${?}" = "1"; then
		sudo dnf install -y bc
	fi
	sudo dnf install -y curl
	curl -s https://packagecloud.io/install/repositories/antpickax/current/script.rpm.sh | sudo bash
	sudo dnf install  k2hdkc-devel -y
elif test "${OS_NAME}" = "debian" -o "${OS_NAME}" = "ubuntu"; then
	which sudo
	if test "${?}" = "1"; then
		apt-get update -y
		apt-get install -y sudo
	fi
	which bc
	if test "${?}" = "1"; then
		sudo apt-get install -y bc
	fi
	sudo apt-get install -y curl
	curl -s https://packagecloud.io/install/repositories/antpickax/stable/script.deb.sh | sudo bash
	sudo apt-get install -y k2hdkc-dev
elif test "${OS_NAME}" = "centos" -o "${OS_NAME}" = "rhel"; then
	which sudo
	if test "${?}" = "1"; then
		if test "${OS_VERSION}" = "7"; then
			sudo yum install -y sudo
		elif test "${OS_VERSION}" = "8"; then
			sudo dnf install -y sudo
		fi
	fi
	which bc
	if test "${?}" = "1"; then
		if test "${OS_VERSION}" = "7"; then
			sudo yum install -y bc
		elif test "${OS_VERSION}" = "8"; then
			sudo dnf install -y bc
		fi
	fi
	if test "${OS_VERSION}" = "7"; then
		sudo yum install -y k2hdkc-devel
	elif test "${OS_VERSION}" = "8"; then
		sudo dnf install -y k2hdkc-devel
	fi
	if test "${?}" != "0"; then
		if test "${OS_VERSION}" = "7"; then
			sudo yum install -y curl
		elif test "${OS_VERSION}" = "8"; then
			sudo dnf install -y curl
		fi
		curl -s https://packagecloud.io/install/repositories/antpickax/stable/script.rpm.sh | sudo bash
		if test "${OS_VERSION}" = "7"; then
			sudo yum install -y k2hdkc-devel
		elif test "${OS_VERSION}" = "8"; then
			sudo dnf install -y k2hdkc-devel
		fi
	fi
else
	echo "[NO] OS must be either fedora or centos or debian or ubuntu, not ${OS_NAME}"
	exit 1
fi

which_k2hdkc
if test "${?}" = "0"; then
	startifnotexist
	exit 0
else
	echo "[NO] k2hdkc"
	exit 1
fi

exit 0

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
