// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *  Copyright (C) 2025  Inomatic GmbH
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"

#include "mosquitto/mqttclient.h"

bt_uuid_t uuidDeviceGAP;
bt_uuid_t uuidDeviceGATT;
bt_uuid_t uuidService;
bt_uuid_t uuidReceive;
bt_uuid_t uuidTransmit;

#define ATT_CID 4

#define PRLOG(...) \
	do { \
		fprintf(stderr,__VA_ARGS__); \
		fflush(stderr); \
	} while (0)


#define COLOR_OFF	"\x1B[0m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_GREEN	"\x1B[0;92m"
#define COLOR_YELLOW	"\x1B[0;93m"
#define COLOR_BLUE	"\x1B[0;94m"
#define COLOR_MAGENTA	"\x1B[0;95m"
#define COLOR_BOLDGRAY	"\x1B[1;30m"
#define COLOR_BOLDWHITE	"\x1B[1;37m"

extern void receivedBtPacket(const uint8_t *value, size_t len);

static const char device_name[] = BUILDVAR_GWBTNAME;
static bool verbose = true;

static time_t lastReceivedBtPacketTime = 0;

struct server {
	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	uint8_t *device_name;
	size_t name_len;

	uint16_t gatt_svc_chngd_handle;
	bool svc_chngd_enabled;

	uint16_t iotgw_handle;
	uint16_t iotgw_data_handle;
	bool iotgw_data_enabled;
};

struct server *g_server;
pthread_mutex_t g_server_lock;

static struct server *server_create(int fd, uint16_t mtu);
int btstart();
static void server_destroy();

static void att_disconnect_cb(int err, void *user_data)
{
	fprintf(stderr,"Device disconnected: %s\n", strerror(err));
	fflush(stderr);

	mqttpublish(BUILDVAR_GWBTCONNECT, "-");
	lastReceivedBtPacketTime = 0;

	server_destroy();

	btstart();
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_BOLDGRAY "%s" COLOR_BOLDWHITE "%s\n" COLOR_OFF, prefix,
									str);
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	PRLOG(COLOR_GREEN "%s%s\n" COLOR_OFF, prefix, str);
}

static void gap_device_name_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;
	size_t len = 0;
	const uint8_t *value = NULL;

	PRLOG("GAP Device Name Read called\n");

	len = server->name_len;

	if (offset > len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	len -= offset;
	value = len ? &server->device_name[offset] : NULL;

done:
	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void gap_device_name_ext_prop_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t value[2];

	PRLOG("Device Name Extended Properties Read called\n");

	value[0] = BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
	value[1] = 0;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_service_changed_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	PRLOG("Service Changed Read called\n");

	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	PRLOG("Service Changed CCC Read called\n");

	value[0] = server->svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	PRLOG("Service Changed CCC Write called\n");

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->svc_chngd_enabled = false;
	else if (value[0] == 0x02)
		server->svc_chngd_enabled = true;
	else
		ecode = 0x80;

	PRLOG("Service Changed Enabled: %s\n",
				server->svc_chngd_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void iotgw_data_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	value[0] = server->iotgw_data_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, 2);
}

static void iotgw_data_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->iotgw_data_enabled = false;
	else if (value[0] == 0x01) {
		if (server->iotgw_data_enabled) {
			PRLOG("Data Already Enabled\n");
			goto done;
		}

		server->iotgw_data_enabled = true;
	} else
		ecode = 0x80;

	PRLOG("Data Enabled: %s\n",
				server->iotgw_data_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void iotgw_data_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	lastReceivedBtPacketTime = time(NULL);

	receivedBtPacket(value, len);

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void populate_gap_service(struct server *server)
{
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance;

	/* Add the GAP service */
	service = gatt_db_add_service(server->db, &uuidDeviceGAP, true, 6);

	/*
	 * Device Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid_t uuid;
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_name_read_cb,
					NULL,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID);
	gatt_db_service_add_descriptor(service, &uuid, BT_ATT_PERM_READ,
					gap_device_name_ext_prop_read_cb,
					NULL, server);

	/*
	 * Appearance characteristic. Reads and writes should obtain the value
	 * from the database.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, server);

	/*
	 * Write the appearance value to the database, since we're not using a
	 * callback.
	 */
	put_le16(128, &appearance);
	gatt_db_attribute_write(tmp, 0, (void *) &appearance,
							sizeof(appearance),
							BT_ATT_OP_WRITE_REQ,
							NULL, NULL,
							NULL);

	gatt_db_service_set_active(service, true);
}

static void populate_gatt_service(struct server *server)
{
	struct gatt_db_attribute *service, *svc_chngd;

	/* Add the GATT service */
	service = gatt_db_add_service(server->db, &uuidDeviceGATT, true, 4);

	bt_uuid_t uuid;
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, server);
	server->gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, server);

	gatt_db_service_set_active(service, true);
}

static void populate_iotgw_service(struct server *server)
{
	struct gatt_db_attribute *service, *iotgw_data;

	service = gatt_db_add_service(server->db, &uuidService, true, 8);
	server->iotgw_handle = gatt_db_attribute_get_handle(service);

	iotgw_data = gatt_db_service_add_characteristic(service, &uuidTransmit,
						BT_ATT_PERM_NONE,
						BT_GATT_CHRC_PROP_NOTIFY,
						NULL, NULL, NULL);
	server->iotgw_data_handle = gatt_db_attribute_get_handle(iotgw_data);

	bt_uuid_t uuid1;
	bt_uuid16_create(&uuid1, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid1,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					iotgw_data_ccc_read_cb,
					iotgw_data_ccc_write_cb, server);

	gatt_db_service_add_characteristic(service, &uuidReceive,
						BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_WRITE,
						NULL, iotgw_data_write_cb,
						server);

	gatt_db_service_set_active(service, true);
}

static void populate_db(struct server *server)
{
	populate_gap_service(server);
	populate_gatt_service(server);
	populate_iotgw_service(server);
}

static struct server *server_create(int fd, uint16_t mtu)
{
	struct server *server;
	size_t name_len = strlen(device_name);

	server = new0(struct server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for server\n");
		return NULL;
	}

	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, NULL,
									NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

	server->name_len = name_len + 1;
	server->device_name = malloc(name_len + 1);
	if (!server->device_name) {
		fprintf(stderr, "Failed to allocate memory for device name\n");
		goto fail;
	}

	memcpy(server->device_name, device_name, name_len);
	server->device_name[name_len] = '\0';

	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, 512 + 5, 0);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	if (verbose) {
		bt_att_set_debug(server->att, BT_ATT_DEBUG_VERBOSE,
						att_debug_cb, "att: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb,
							"server: ", NULL);
	}

	/* Random seed for generating fake Heart Rate measurements */
	srand(time(NULL));

	/* bt_gatt_server already holds a reference */
	populate_db(server);

	return server;

fail:
	gatt_db_unref(server->db);
	free(server->device_name);
	bt_att_unref(server->att);
	free(server);

	return NULL;
}

static void server_destroy()
{
	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		bt_gatt_server_unref(g_server->gatt);
		gatt_db_unref(g_server->db);
		free(g_server->device_name);
		bt_att_unref(g_server->att);
		free(g_server);
		g_server = NULL;
	}
	pthread_mutex_unlock(&g_server_lock);
}

static int sockL2CAP = -1;
static int sockConn = -1;

static int l2cap_le_att_listen(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	struct sockaddr_l2 srcaddr;
	struct bt_security btsec;

	sockL2CAP = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sockL2CAP < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(sockL2CAP, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sockL2CAP, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	fcntl(sockL2CAP, F_SETFL, O_NONBLOCK);

	if (listen(sockL2CAP, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	fprintf(stderr,"Started listening on ATT channel. Waiting for connections\n");
	fflush(stderr);
	return 0;

fail:
	close(sockL2CAP);
	return -1;
}

static int l2cap_le_att_accept(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	struct sockaddr_l2 addr;
	socklen_t optlen;
	char ba[18];

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	sockConn = accept(sockL2CAP, (struct sockaddr *) &addr, &optlen);
	if (sockConn < 0) {
		return -1;
	}

	ba2str(&addr.l2_bdaddr, ba);

	mqttpublish(BUILDVAR_GWBTCONNECT, ba);

	close(sockL2CAP);

	return sockConn;
}

void sendBtNotification(const uint8_t *value, size_t length) {
	pthread_mutex_lock(&g_server_lock);
	if (g_server != NULL) {
		if (g_server->iotgw_data_enabled) {
			if (!bt_gatt_server_send_notification(g_server->gatt, g_server->iotgw_data_handle, value, length, false)) {
				fprintf(stderr,"Failed to initiate notification\n");
				fflush(stderr);
			}
		}
	}
	pthread_mutex_unlock(&g_server_lock);
}

char btaddr[19];
void get_bt_mac_addr() {
	int dev_id = hci_get_route(NULL);
	if (dev_id < 0) {
		sprintf(btaddr, "00:00:00:00:00:00");
	}

	int sock = hci_open_dev(dev_id);
	if (sock < 0) {
		sprintf(btaddr, "00:00:00:00:00:01");
	}

	bdaddr_t bdaddr;
	if (hci_devba(dev_id, &bdaddr) < 0) {
		sprintf(btaddr, "00:00:00:00:00:02");
	}

	ba2str(&bdaddr, btaddr);
	close(sock);
}

int btinit()
{
	pthread_mutexattr_t mutex_attr;
	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&g_server_lock, &mutex_attr);

	get_bt_mac_addr();

	mainloop_init();

	bt_uuid16_create(&uuidDeviceGAP, 0x1800);
	bt_uuid16_create(&uuidDeviceGATT, 0x1801);
	bt_string_to_uuid(&uuidService, BUILDVAR_GWBTSERVICEUUID);
	bt_string_to_uuid(&uuidReceive, BUILDVAR_GWBTRECEIVEUUID);
	bt_string_to_uuid(&uuidTransmit, BUILDVAR_GWBTTRANSMITUUID);

	return btstart();
}

static int fdL2CAP;

int btstart() {

	sockL2CAP = -1;
	sockConn = -1;
	fdL2CAP = -1;

	server_destroy();

	fprintf(stderr,"Running GATT server\n");

	return EXIT_SUCCESS;
}

bool bHwaddrSent = false;

int btloop() {
	if (sockL2CAP < 0) {
		bdaddr_t src_addr;
		int dev_id = -1;
		int sec = BT_SECURITY_LOW;
		uint8_t src_type = BDADDR_LE_PUBLIC;

		if (dev_id == -1)
			bacpy(&src_addr, BDADDR_ANY);
		else if (hci_devba(dev_id, &src_addr) < 0) {
			perror("Adapter not available");
			return EXIT_FAILURE;
		}

		int res = l2cap_le_att_listen(&src_addr, sec, src_type);
		if (res != 0) {
			fprintf(stderr, "Failed to listen for L2CAP ATT connection\n");
			return EXIT_FAILURE;
		}
	} else if (sockConn < 0) {
		bdaddr_t src_addr;
		int dev_id = -1;
		int sec = BT_SECURITY_LOW;
		uint8_t src_type = BDADDR_LE_PUBLIC;
		uint16_t mtu = 0;

		if (dev_id == -1)
			bacpy(&src_addr, BDADDR_ANY);
		else if (hci_devba(dev_id, &src_addr) < 0) {
			perror("Adapter not available");
			return EXIT_FAILURE;
		}

		fdL2CAP = l2cap_le_att_accept(&src_addr, sec, src_type);
		if (fdL2CAP >= 0) {

			pthread_mutex_lock(&g_server_lock);

			g_server = server_create(fdL2CAP, mtu);
			if (!g_server) {
				close(fdL2CAP);
				pthread_mutex_unlock(&g_server_lock);
				return EXIT_FAILURE;
			}
			pthread_mutex_unlock(&g_server_lock);

			fprintf(stderr,"Running GATT server\n");
		}
	}

	if (lastReceivedBtPacketTime != 0 && time(NULL) - lastReceivedBtPacketTime > 20) {
		fprintf(stderr,"No data received for 20 seconds, disconnecting\n");
		fflush(stderr);

		mqttpublish(BUILDVAR_GWBTCONNECT, "-");
		lastReceivedBtPacketTime = 0;

		server_destroy();
		return btstart();
	}

	if (mainloop_iteration()) {
		return EXIT_FAILURE;
	}

	if (!bHwaddrSent) {
		if (mqttpublish("bluetooth/hwaddr", btaddr) > 0) {
			bHwaddrSent = true;
		}
	}

	return EXIT_SUCCESS;
}

int btquit() {
	fprintf(stderr,"\n\nShutting down...\n");

	mainloop_finish();

	server_destroy();

	pthread_mutex_destroy(&g_server_lock);

	return EXIT_SUCCESS;
}

