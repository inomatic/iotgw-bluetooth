#define _XOPEN_SOURCE 700

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>

#include "client_shared.h"

#define UNUSED(x) (void)(x)

int mid_sent = -1;
struct mosq_config cfg = {0};

enum rr__state {
	rr_s_new,
	rr_s_connected,
	rr_s_subscribed,
	rr_s_ready_to_publish,
	rr_s_wait_for_response,
	rr_s_disconnect
};

static enum rr__state client_state = rr_s_new;

bool process_messages = true;
int msg_count = 0;
struct mosquitto *g_mosq = NULL;
static bool timed_out = false;
static int connack_result = 0;

#ifndef WIN32
static void my_signal_handler(int signum)
{
	if(signum == SIGALRM){
		process_messages = false;
		mosquitto_disconnect_v5(g_mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
		timed_out = true;
	}
}
#endif


int my_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
	if(cfg.protocol_version < MQTT_PROTOCOL_V5){
		return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, NULL);
	}else{
		return mosquitto_publish_v5(mosq, mid, topic, payloadlen, payload, qos, retain, cfg.publish_props);
	}
}

void (*on_message)(const char *, const uint8_t *, size_t) = NULL;
void (*on_connected)() = NULL;

static void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(properties);

	if(process_messages == false) return;
	if(message->retain && cfg.no_retain) return;

	if (strcmp(message->topic, BUILDVAR_GWBTQUIT) == 0) {
		process_messages = false;
		mosquitto_disconnect_v5(g_mosq, MQTT_RC_DISCONNECT_WITH_WILL_MSG, cfg.disconnect_props);
	}

	if (on_message != NULL) {
		on_message(message->topic, message->payload, message->payloadlen);
	}
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(level);

	printf("%s\n", str);
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(flags);
	UNUSED(properties);

	connack_result = result;
	if(!result){
		client_state = rr_s_connected;
		if (on_connected != NULL) {
			on_connected();
		}
	}else{
		client_state = rr_s_disconnect;
		if(result){
			if(result == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION){
				err_printf(&cfg, "Connection error: %s. mosquitto_rr only supports connecting to an MQTT v5 broker\n", mosquitto_reason_string(result));
			}else{
				err_printf(&cfg, "Connection error: %s\n", mosquitto_reason_string(result));
			}
		} else {
			printf("Connection error!\n");
		}
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}


static void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	UNUSED(obj);
	UNUSED(mid);
	UNUSED(qos_count);

	if(granted_qos[0] < 128){
		client_state = rr_s_ready_to_publish;
	}else{
		client_state = rr_s_disconnect;
		err_printf(&cfg, "%s\n", mosquitto_reason_string(granted_qos[0]));
		mosquitto_disconnect_v5(mosq, 0, cfg.disconnect_props);
	}
}


void my_publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	UNUSED(mosq);
	UNUSED(obj);
	UNUSED(mid);

	client_state = rr_s_wait_for_response;
}

static char s_clientidprefix[1024];

int mqttinit(const char *clientidprefix, void (*p_on_message)(const char *, const uint8_t *, size_t), void (*p_on_connected)())
{
	on_message = p_on_message;
	on_connected = p_on_connected;

	snprintf(s_clientidprefix, sizeof(s_clientidprefix), "%s", clientidprefix);

	int rc;
#ifndef WIN32
		struct sigaction sigact;
#endif

	mosquitto_lib_init();

	init_config(&cfg);
	cfg.id_prefix = s_clientidprefix;
	cfg.host = BUILDVAR_GWBTMQTTHOST;
	cfg.port = BUILDVAR_GWBTMQTTPORT;
	cfg.username = BUILDVAR_GWBTMQTTUSER;
	cfg.password = BUILDVAR_GWBTMQTTPASSWORD;
	cfg.publish_props = NULL;
	cfg.retain = 0;
	cfg.no_retain = true;
	cfg.sub_opts |= MQTT_SUB_OPT_SEND_RETAIN_NEVER | MQTT_SUB_OPT_NO_LOCAL;

	if(client_id_generate(&cfg)){
		return 1;
	}

	g_mosq = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!g_mosq){
		switch(errno){
			case ENOMEM:
				err_printf(&cfg, "Error: Out of memory.\n");
				break;
			case EINVAL:
				err_printf(&cfg, "Error: Invalid id and/or clean_session.\n");
				break;
		}
		return 1;
	}
	if(client_opts_set(g_mosq, &cfg)){
		return 1;
	}
	if(cfg.debug){
		mosquitto_log_callback_set(g_mosq, my_log_callback);
	}
	mosquitto_connect_v5_callback_set(g_mosq, my_connect_callback);
	mosquitto_subscribe_callback_set(g_mosq, my_subscribe_callback);
	mosquitto_message_v5_callback_set(g_mosq, my_message_callback);
	mosquitto_publish_callback_set(g_mosq, my_publish_callback);

	rc = client_connect(g_mosq, &cfg);
	if(rc){
		return rc;
	}

#ifndef WIN32
	sigact.sa_handler = my_signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;

	if(sigaction(SIGALRM, &sigact, NULL) == -1){
		perror("sigaction");
		return 1;
	}

	if(cfg.timeout){
		alarm(cfg.timeout);
	}
#endif

	return 0;
}

int lastrc;

int mqttloop() {
	lastrc = mosquitto_loop(g_mosq, 0, 1);
	if(client_state == rr_s_ready_to_publish){
		client_state = rr_s_wait_for_response;
	}
	if (lastrc != MOSQ_ERR_SUCCESS) {
		printf("MQTT no success %d\n", lastrc);
	}
	return (lastrc == MOSQ_ERR_SUCCESS && client_state != rr_s_disconnect);
}

static int msgcount = 1;

int mqttpublishbinary(const char *topic, const uint8_t *bytes, size_t len) {
	int x = msgcount++;
	if (my_publish(g_mosq, &x, topic, len, bytes, 2/*QoS*/, false/*retain*/) == MOSQ_ERR_SUCCESS) {
		return x;
	}
	return 0;
}

int mqttpublish(const char *topic, const char *message) {
	int x = msgcount++;
	if (my_publish(g_mosq, &x, topic, strlen(message), message, 2/*QoS*/, false/*retain*/) == MOSQ_ERR_SUCCESS) {
		return x;
	}
	return 0;
}

int mqttsubscribe(const char *topic, int qos) {
	int x = msgcount++;
	mosquitto_subscribe_v5(g_mosq, &x, topic, qos, 0, cfg.subscribe_props);
	return x;
}

int mqttquit() {
	mosquitto_destroy(g_mosq);
	mosquitto_lib_cleanup();

	int rc = lastrc;

	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN){
		rc = 0;
	}
	client_config_cleanup(&cfg);
	if(timed_out){
		err_printf(&cfg, "Timed out\n");
		return MOSQ_ERR_TIMEOUT;
	}else if(rc){
		err_printf(&cfg, "Error: %s\n", mosquitto_strerror(rc));
	}
	if(connack_result){
		return connack_result;
	}else{
		return rc;
	}

	mosquitto_lib_cleanup();
	client_config_cleanup(&cfg);
	return 1;
}