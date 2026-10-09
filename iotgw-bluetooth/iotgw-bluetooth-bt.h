#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

typedef struct {
	time_t lastReceivedBtPacketTime;

	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	uint8_t *device_name;
	size_t name_len;

	uint16_t gatt_svc_chngd_handle;
	bool svc_chngd_enabled;

	uint16_t iotgw_dataservice_handle;
	uint16_t iotgw_data_handle_aes256;
	uint16_t iotgw_data_handle_c20_tx;

	uint16_t iotgw_devinfo_handle;
	bool iotgw_data_enabled;

	uint64_t serverid;
	bool c20_enabled;
} server_t;

#define MaxServers 5

extern void receivedBtChacha20Poly1305AEADPacket(const uint8_t *value, size_t len);
extern void receivedBtC20PacketRx(const uint8_t *value, size_t len, server_t *server);
extern void receivedBtPacket(const uint8_t *value, size_t len);

