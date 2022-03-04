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

echo $(basename $0)

if test -f "/etc/os-release"; then
    . /etc/os-release
    OS_NAME=$ID
    OS_VERSION=$VERSION_ID
elif test -f "/etc/centos-release"; then
    echo "[OK] /etc/centos-release falling back to CentOS-7"
    OS_NAME=centos
    OS_VERSION=7
else
    echo "Unknown OS, neither /etc/os-release nor /etc/centos-release"
    exit 1
fi

echo "[OK] HOSTNAME=${HOSTNAME} OS_NAME=${OS_NAME} OS_VERSION=${OS_VERSION}"
cd src

pylint k2hdkc --py3k -r n

exit $?

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
