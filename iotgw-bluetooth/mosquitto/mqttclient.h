
int mqttinit(const char *clientidprefix, void (*p_on_message)(const char *, const uint8_t *, size_t), void (*p_on_connected)());
int mqttsubscribe(const char *topic, int qos);
int mqttpublishbinary(const char *topic, const uint8_t *bytes, size_t len);
int mqttpublish(const char *topic, const char *message);
int mqttloop();
int mqttquit();
