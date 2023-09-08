/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define WEBCFG_ELEMENTS 3
#define SUBSCRIBE_WEBCONFIG "webconfig"

#define WEBCFG_MQTT_SUBSCRIBE_CALLBACK "Device.X_RDK_MQTT.Webconfig.OnSubcribeCallback"
#define WEBCFG_MQTT_ONMESSAGE_CALLBACK "Device.X_RDK_MQTT.Webconfig.OnMessageCallback"
#define WEBCFG_MQTT_ONPUBLISH_CALLBACK "Device.X_RDK_MQTT.Webconfig.OnPublishCallback"

#define MQTT_PUBLISH_NOTIFY_TOPIC_PREFIX "x/fr/"
#define MAX_MQTT_LEN         128

int rbusRegWebcfgDataElements();
rbusError_t sendRbusEventWebcfgOnSubscribe();
rbusError_t sendRbusEventWebcfgOnMessage(char *mqttdata, int dataSize, char *topic_name);
rbusError_t sendRbusEventWebcfgOnPublish(int mid);
int sendRbusErrorToMqtt(rbusError_t rc, char *topic_name);
char * createcJsonSchema(rbusError_t rc, char *topic_name);
char * createMqttPubHeader(char * payload, ssize_t * payload_len);
