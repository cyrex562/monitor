#!/usr/bin/env bash
# create directories
mkdir -p /opt/monitor


# install apt packages
apt-get update
apt-get dist-upgrade
apt install autoconf automake build-essential libtool pkg-config texinfo zlib1g-dev yasm cmake mercurial python3-setuptools libssl-dev redis-server redis-tools python3-pip python3-dev supervisor git ntp inetutils-traceroute iputils-tracepath iputils-arping libpcap-dev sysdig libffi-dev nginx htop iotop jnettop nmap tshark bird lldpad lldpad ladvd avahi-daemon mdns-scan libgmp-dev

# install pip packages
pip3 install psutil jsonpickle gunicorn pycrypto netifaces redis pexpect service_identity pyopenssl bottle pyyaml couchdb

# install strongswan from source
cd /usr/local/src
wget https://download.strongswan.org/strongswan-5.5.0.tar.bz2
tar xf strongswan-*
cd strongswan-*
./configure --prefix=/usr --sysconfdir=/etc
make
make install

cd /usr/local/src

# openvpn from source

# olsr from source

# bird from source

# ffmpeg dependencies
apt install libx264-dev libmp3lame-dev libopus-dev libass-dev libfreetype6-dev  libsdl1.2-dev libtheora-dev libva-dev libvdpau-dev libvorbis-dev libxcb1-dev libxcb-shm0-dev libxcb-xfixes0-dev