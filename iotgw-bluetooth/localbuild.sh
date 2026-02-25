#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

make clean
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
export BUILDVAR_GWBTMQTTUSER="bluetooth"
export BUILDVAR_GWBTMQTTPASSWORD="ino"
make -j 20 iotgw-bluetooth
