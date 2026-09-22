#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

IP=$1

source /opt/dev-tools/oecore-x86_64/environment-setup-cortexa7t2hf-neon-vfpv4-oe-linux-gnueabi

export BUILDVAR_GWBTNAME="Inomatic IoT-Gateway"
export BUILDVAR_GWBTCONNECT="bluetooth/connect"
export BUILDVAR_GWBTSERVICEUUID="6E400001-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTRECEIVEACKUUID="6E400002-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTTRANSMITUUID="6E400003-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTRECEIVENOACKUUID="6E400004-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTRECEIVECHACHA20POLY1305AEADUUID="6E400005-C352-11E5-953D-0002A5D5C51B"
export BUILDVAR_GWBTSTATUS="bluetooth/status"
export BUILDVAR_GWBTBTGWFRAME="gateway/bluetoothframe"
export BUILDVAR_GWBTBTBTFRAME="bluetooth/bluetoothframe"
export BUILDVAR_GWBTBTBTCHACHA20POLY1305AEADFRAME="bluetooth/bluetoothframe_chacha20poly1305aead"
export BUILDVAR_GWBTCLIENTID="iotgw-bluetooth"
export BUILDVAR_GWBTQUIT="global/quit"
export BUILDVAR_GWBTMQTTHOST="127.0.0.1"
export BUILDVAR_GWBTMQTTPORT=1884
export BUILDVAR_GWBTMQTTUSER="iotgw-bluetooth"
export BUILDVAR_GWBTMQTTPASSWORD="InoM4t1c_Passw0rd-FOr=Blu3t0th"
make iotgw-bluetooth

echo "Stopping iotgw-bluetooth"
ssh -p 22 root@$IP "(systemctl stop iotgw-bluetooth ; killall -9 iotgw-bluetooth ; killall -9 gdbserver) || true"
echo "Stopping avahi-daemon and remount rw"
ssh -p 22 root@$IP "systemctl stop avahi-daemon.socket ; systemctl stop avahi-daemon ; umount /etc ; mount -n -o remount,rw /"
echo "Uploading iotgw-bluetooth"
scp -P 22 iotgw-bluetooth root@$IP:/usr/bin/iotgw-bluetooth
echo "remount ro and reboot"
ssh -p 22 root@$IP "mount -n -o remount,ro / ; sync ; sleep 1 ; sync ; reboot"
echo "Upload done."
