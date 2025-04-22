#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <vector>
#include <string>
#include <sstream>
#include <inttypes.h>

std::vector<uint8_t> HexToBytes(const std::string &hex)
{
  std::vector<uint8_t> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2)
  {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

bool isConnected = false;

extern "C"
{
  extern void sendBtNotification(const uint8_t *value, size_t length);

#include "mosquitto/mqttclient.h"

  static void mqtt_connected_callback()
  {
    printf("Connected to MQTT broker\n");
    isConnected = true;

    mqttsubscribe("#", 2);
  }

  static void mqtt_message_callback(const char *topic, const uint8_t *bytes, size_t len)
  {
    if (strcmp(topic, BUILDVAR_GWBTBTGWFRAME) == 0)
    {
      sendBtNotification(bytes, len);
    }
  }

  extern int btinit();
  extern int btquit();
  extern int btloop();

  volatile bool g_quit = false;

  void receivedBtPacket(const uint8_t *value, size_t len)
  {
    mqttpublishbinary(BUILDVAR_GWBTBTBTFRAME, value, len);
  }

  static void intHandler(int /*signum*/)
  {
    g_quit = true;
  }

  int main(int argc, char *argv[])
  {
    signal(SIGINT, intHandler);
    signal(SIGKILL, intHandler);

    mqttinit(BUILDVAR_GWBTCLIENTID, mqtt_message_callback, mqtt_connected_callback);

    int i = btinit();
    if (i != EXIT_SUCCESS)
    {
      printf("Bluetooth failed to initialize\n");
      return i;
    }

    uint32_t uiLastOnlineSent = 0;

    do
    {
      if (!mqttloop())
      {
        printf("MQTT failed\n");
        g_quit = true;
      }

      if (btloop() != EXIT_SUCCESS)
      {
        printf("BT failed\n");
        g_quit = true;
      }

      uint32_t now = time(NULL);
      if (isConnected && uiLastOnlineSent + 0 < now) {
        uiLastOnlineSent = now;
        char timestr[32];
        snprintf(timestr, sizeof(timestr), "%"PRIu32, time(NULL));
        mqttpublish("public/" BUILDVAR_GWBTSTATUS, timestr);
      }

    } while (!g_quit);

    printf("Quitting MQTT...\n");
    mqttquit();

    printf("Quitting BT...\n");
    btquit();

    return 0;
  }
}
