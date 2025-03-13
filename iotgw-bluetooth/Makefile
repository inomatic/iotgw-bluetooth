COMMONFLAGS = -I.. -DBUILDVAR_GWBTNAME="\"$(BUILDVAR_GWBTNAME)\"" -DBUILDVAR_GWBTCONNECT="\"$(BUILDVAR_GWBTCONNECT)\"" -DBUILDVAR_GWBTSERVICEUUID="\"$(BUILDVAR_GWBTSERVICEUUID)\"" -DBUILDVAR_GWBTRECEIVEUUID="\"$(BUILDVAR_GWBTRECEIVEUUID)\"" -DBUILDVAR_GWBTTRANSMITUUID="\"$(BUILDVAR_GWBTTRANSMITUUID)\"" -DBUILDVAR_GWBTSTATUS="\"$(BUILDVAR_GWBTSTATUS)\"" -DBUILDVAR_GWBTBTGWFRAME="\"$(BUILDVAR_GWBTBTGWFRAME)\"" -DBUILDVAR_GWBTBTBTFRAME="\"$(BUILDVAR_GWBTBTBTFRAME)\"" -DBUILDVAR_GWBTCLIENTID="\"$(BUILDVAR_GWBTCLIENTID)\"" -DBUILDVAR_GWBTQUIT="\"$(BUILDVAR_GWBTQUIT)\"" -DBUILDVAR_GWBTMQTTHOST="\"$(BUILDVAR_GWBTMQTTHOST)\"" -DBUILDVAR_GWBTMQTTPORT=$(BUILDVAR_GWBTMQTTPORT) -DBUILDVAR_GWBTMQTTUSER="\"$(BUILDVAR_GWBTMQTTUSER)\"" -DBUILDVAR_GWBTMQTTPASSWORD="\"$(BUILDVAR_GWBTMQTTPASSWORD)\""

CFLAGS := -O2 -Wall -Ibluez -fno-exceptions -g -Og $(COMMONFLAGS)
CXXFLAGS := -O3 -Wall -fno-exceptions -g -Og $(COMMONFLAGS)

.SUFFIXES: .c .cxx

all:	iotgw-bluetooth
	echo ok

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

.cxx.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@


MOSQUITTO_OBJ = mosquitto/mosquitto.o mosquitto/client_shared.o mosquitto/client_props.o

IOTGW_BLUETOOTH_OBJ = ${MOSQUITTO_OBJ} iotgw-bluetooth.o iotgw-bluetooth-bt.o ../src/shared/att.o ../src/shared/hci.o ../src/shared/io-mainloop.o ../src/shared/mainloop.o ../src/shared/queue.o ../src/shared/util.o ../src/shared/crypto.o ../src/shared/mainloop-notify.o ../src/shared/gatt-helpers.o ../src/shared/gatt-client.o ../src/shared/gatt-server.o ../src/shared/gatt-db.o ../src/shared/timeout-mainloop.o ../lib/uuid.o

iotgw-bluetooth:	 ${IOTGW_BLUETOOTH_OBJ}
	cp /opt/dev-tools/oecore-x86_64/sysroots/cortexa7t2hf-neon-vfpv4-oe-linux-gnueabi/usr/lib/crt*.o .
	cp /opt/dev-tools/oecore-x86_64/sysroots/cortexa7t2hf-neon-vfpv4-oe-linux-gnueabi/usr/lib/arm-oe-linux-gnueabi/13.3.0/crt*.o .
	$(CXX) $(IOTGW_BLUETOOTH_OBJ) -lmosquitto -lbluetooth -lc -lstdc++ -o iotgw-bluetooth

clean:
	rm ${IOTGW_BLUETOOTH_OBJ} crt*.o iotgw-bluetooth 2> /dev/null || true
