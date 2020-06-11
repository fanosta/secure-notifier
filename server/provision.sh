#!/bin/sh
set -eu

cd $(dirname $(readlink -f $0))

go build
scp ./server iridium:~/server
ssh -t iridium ./install_server.sh
