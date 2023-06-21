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

#ifndef MQTTCM_CONN_H_INCLUDED
#define MQTTCM_CONN_H_INCLUDED

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "mqttcm_log.h"

#define MQTT_PUBLISH_PARAM        "Device.X_RDK_MQTT.Publish"
#define MQTT_CONNSTATUS_PARAM     "Device.X_RDK_MQTT.ConnectionStatus"

typedef enum 
{
	MQTTCM_CONN_STATUS_UNKNOWN      = 0,
	MQTTCM_CONN_STATUS_CONNECTED    = 1,
	MQTTCM_CONN_STATUS_DISCONNECTED = 2,  
} mqttcm_conn_status_t;

typedef struct {
	char *broker_url;
	unsigned int port;  
} mqttcm_conn_config_t;

typedef struct {
	void *msg;
	unsigned int msg_len;
	bool do_compress;
	char *qos;
	char *topic;
} mqttcm_conn_msg_t;

typedef struct {
	int (*mqttcm_connected_cb)(void *);
	int (*mqttcm_disconnected_cb)(void *);
	int (*mqttcm_subscribe_cb)(void *);
	int (*mqttcm_publish_cb)(void *);
} mqttcm_conn_cb_t;

typedef struct {
	unsigned int conn_id; 
	mqttcm_conn_cb_t cbs;
} mqttcm_conn_t;

int mqttcm_conn_init(mqttcm_conn_t *connector);
int mqttcm_conn_config_set(mqttcm_conn_config_t *conn_config);
int mqttcm_conn_status_get(mqttcm_conn_t *connector);
int mqttcm_conn_publish(mqttcm_conn_msg_t *msg);
int mqttcm_conn_close(mqttcm_conn_t *connector);

int mqttcm_conn_process_messages(void *msg, unsigned int mesg_len, bool do_compress, char *topic, char *qos);
int mqttcm_conn_getMqttCMConnStatus();
int mqttcm_conn_publish_messages(char *msg, char *topic, char *qos);
int mqttcm_conn_compress_messages();

#endif /* MQTTCM_CONN_H_INCLUDED */
