#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

IP=$1

#ssh-keygen -f '/home/alex/.ssh/known_hosts' -R "$IP"

source /opt/dev-tools/oecore-x86_64/environment-setup-cortexa7t2hf-neon-vfpv4-oe-linux-gnueabi

export BUILDVAR_GWBTNAME="Inomatic IoT-Gateway"
export BUILDVAR_GWBTCONNECT="bluetooth/connect"
export BUILDVAR_GWBTSERVICEUUID="6E400001-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTRECEIVEUUID="6E400002-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTTRANSMITUUID="6E400003-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTSTATUS="bluetooth/status"
export BUILDVAR_GWBTBTGWFRAME="gateway/bluetoothframe"
export BUILDVAR_GWBTBTBTFRAME="bluetooth/bluetoothframe"
export BUILDVAR_GWBTCLIENTID="iotgw-bluetooth"
export BUILDVAR_GWBTQUIT="global/quit"
export BUILDVAR_GWBTMQTTHOST="127.0.0.1"
export BUILDVAR_GWBTMQTTPORT=1884
export BUILDVAR_GWBTMQTTUSER="iotgw-bluetooth"
export BUILDVAR_GWBTMQTTPASSWORD="InoM4t1c_Passw0rd-FOr=Blu3t0th"
make iotgw-bluetooth

ssh -p 22 root@$IP "(systemctl stop iotgw-bluetooth ; killall -9 iotgw-bluetooth ; killall -9 gdbserver) || true"
scp -P 22 iotgw-bluetooth root@$IP:/usr/bin/
echo "Upload done."
