#!/bin/bash
set -e


# Set variables
export NPROCS=$(nproc)
export RELEASE="development"
export BUILDVER="$(date +%Y)$(date +%m)$(date +%d)"
export BUILDITERATION=999
export OS=$(lsb_release -sc)
export ARCH=$(dpkg --print-architecture)
export DIST=$(grep ^ID= /etc/*release | awk -F'=' '{ print $2 }')
export FULLBUILDVER="${BUILDVER}.${BUILDITERATION}+${RELEASE}~${OS}"
export VENDOR="Syncwerk GmbH"
export VENDOREMAIL="support@syncwerk.com"
export MAINTAINER="${VENDOR} <${VENDOREMAIL}>"
export DATERFC=$(date --rfc-2822)
export PUBLISHONPUBILCREPO=False
lsb_release -si | grep -qi "debian" && export DEBSTDVER=3.9.8
lsb_release -si | grep -qi "ubuntu" && export DEBSTDVER=3.9.7


function build {
cat <<EOF


Creating syncwerk-server-restapi_${FULLBUILDVER}_${ARCH}.deb
------------------------------------------------------------------------------------------------------

EOF
cat debian/control.template | envsubst | sed 's/\\\$/$/g' > debian/control
cat debian/changelog.template | envsubst > debian/changelog
cat debian/copyright.template | envsubst > debian/copyright
sed -i "s/^SYNCWERK_VERSION.*/SYNCWERK_VERSION = \"${FULLBUILDVER}\"/g" fhs/usr/share/python/syncwerk/restapi/restapi/settings.py
debuild -us -uc
}


function install {
cat <<EOF


Installing ../syncwerk-server-restapi_${FULLBUILDVER}_${ARCH}.deb
------------------------------------------------------------------------------------------------------

EOF
dpkg -i ../syncwerk-server-restapi_${FULLBUILDVER}_${ARCH}.deb


cat <<EOF


Killing web-service process to trigger watchguard restart
------------------------------------------------------------------------------------------------------

EOF
pkill -ef web-service


cat <<EOF


Showing current server.log entries for 10 seconds
------------------------------------------------------------------------------------------------------

EOF

(tail -f /var/log/syncwerk/server.log & PID=$! ; sleep 10 ; kill -9 ${PID})


cat <<EOF


New process IDs of web-service
------------------------------------------------------------------------------------------------------

EOF
pidof web-service


cat <<EOF


Finished, execution time:
------------------------------------------------------------------------------------------------------
EOF
}


# Get options and execute task
while true ; do
    case "$1" in
        build-stable) time (export RELEASE="stable" ; build) ; echo ; break ;;
        build-unstable) time (export RELEASE="unstable" ; build) ; echo ; break ;;
        *) time (build ; install) ; echo ; break ;;
    esac
done
