#!/usr/bin/env bash

apt-get update
apt-get install apt-transport-https ca-certificates -y
apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 \
    --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
echo "deb https://apt.dockerproject.org/repo debian-jessie main" > \
    /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install docker-engine git vim -y
adduser vagrant docker

mkdir /srv/rsync-backup

cat > /home/vagrant/.vimrc << EOF
set background=dark
set tabstop=4
set shiftwidth=4
set expandtab
syntax on
set textwidth=80
set colorcolumn=+1
set formatoptions-=t
EOF