# -fsanitize=address  -lasan 
COMMONFLAGS = -I.. -DBUILDVAR_GWBTNAME="\"$(BUILDVAR_GWBTNAME)\"" -DBUILDVAR_GWBTCONNECT="\"$(BUILDVAR_GWBTCONNECT)\"" -DBUILDVAR_GWBTSERVICEUUID="\"$(BUILDVAR_GWBTSERVICEUUID)\"" -DBUILDVAR_GWBTRECEIVEACKUUID="\"$(BUILDVAR_GWBTRECEIVEACKUUID)\"" -DBUILDVAR_GWBTTRANSMITUUID="\"$(BUILDVAR_GWBTTRANSMITUUID)\"" -DBUILDVAR_GWBTRECEIVENOACKUUID="\"$(BUILDVAR_GWBTRECEIVENOACKUUID)\"" -DBUILDVAR_GWBT_C20_RX_UUID="\"$(BUILDVAR_GWBT_C20_RX_UUID)\"" -DBUILDVAR_GWBT_C20_TX_UUID="\"$(BUILDVAR_GWBT_C20_TX_UUID)\"" -DBUILDVAR_GWBTSTATUS="\"$(BUILDVAR_GWBTSTATUS)\"" -DBUILDVAR_GWBTBTGWFRAME="\"$(BUILDVAR_GWBTBTGWFRAME)\"" -DBUILDVAR_GWBTBTGWSETPOINT="\"$(BUILDVAR_GWBTBTGWSETPOINT)\"" -DBUILDVAR_GWBTBTBTFRAME="\"$(BUILDVAR_GWBTBTBTFRAME)\"" -DBUILDVAR_GWBTBTBTCHACHA20POLY1305AEADFRAME="\"$(BUILDVAR_GWBTBTBTCHACHA20POLY1305AEADFRAME)\"" -DBUILDVAR_GWBTBTBT_C20_RX="\"$(BUILDVAR_GWBTBTBT_C20_RX)\"" -DBUILDVAR_GWBTBTBT_C20_TX="\"$(BUILDVAR_GWBTBTBT_C20_TX)\"" -DBUILDVAR_GWBTCLIENTID="\"$(BUILDVAR_GWBTCLIENTID)\"" -DBUILDVAR_GWBTQUIT="\"$(BUILDVAR_GWBTQUIT)\"" -DBUILDVAR_GWBTMQTTHOST="\"$(BUILDVAR_GWBTMQTTHOST)\"" -DBUILDVAR_GWBTMQTTPORT=$(BUILDVAR_GWBTMQTTPORT) -DBUILDVAR_GWBTMQTTUSER="\"$(BUILDVAR_GWBTMQTTUSER)\"" -DBUILDVAR_GWBTMQTTPASSWORD="\"$(BUILDVAR_GWBTMQTTPASSWORD)\""

CFLAGS := -Wall -Ibluez -fno-exceptions -g $(COMMONFLAGS)
CXXFLAGS := -Wall -fno-exceptions -g $(COMMONFLAGS)

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
	cp ../../recipe-sysroot/usr/lib/arm-oe-linux-gnueabi/13.3.0/crt*.o . || true
	cp ../../recipe-sysroot/usr/lib/crt*.o . || true
	$(CXX) $(IOTGW_BLUETOOTH_OBJ) -lmosquitto -lbluetooth -lc -lstdc++ -o iotgw-bluetooth

clean:
	rm ${IOTGW_BLUETOOTH_OBJ} crt*.o iotgw-bluetooth 2> /dev/null || true
