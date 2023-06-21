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

#include <stdio.h>
#include <rbus/rbus.h>
#include <rbus/rbus_object.h>
#include <rbus/rbus_property.h>
#include <rbus/rbus_value.h>

#include "mqttcm_conn.h"

#define MQTT_COMPONENT_NAME "mqttConnManager"

static rbusHandle_t rbus_handle;

rbusHandle_t get_global_rbus_handle(void);

int mqttcm_conn_initialization()
{   
    int ret = RBUS_ERROR_SUCCESS;  
  
    ret = rbus_open(&rbus_handle,"MQTT_COMPONENT_NAME");
    if (ret != RBUS_ERROR_SUCCESS)
    {
        MqttCMError("%s: Rbus open failed for MQTTCM from  MqttCM lib, err=%d\n",__func__,ret);
        return 0;
    }
     return 1;
}

rbusHandle_t get_global_rbus_handle(void)
{
     return rbus_handle;
}

int mqttcm_conn_compress_messages()
{

    MqttCMInfo("%s: Messages are compressed successfully",__func__);
    return 0;
}

int mqttcm_conn_publish_messages(char *msg, char *topic, char *qos)
{
    bool ret = false; 
    rbusObject_t inParams;
    rbusObject_t outParams;
    rbusValue_t  value;
    rbusError_t err = RBUS_ERROR_BUS_ERROR;

    rbusObject_Init(&inParams, NULL);
    rbusObject_Init(&outParams, NULL);

    rbusValue_Init(&value);
    rbusValue_SetString(value, msg);
    MqttCMInfo("%s: Messages passed to Mqttcm lib before publishing to rbus : %s",__func__,msg);
    rbusObject_SetValue(inParams, "payload", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, topic); 
    rbusObject_SetValue(inParams, "topic", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, qos); 
    rbusObject_SetValue(inParams, "qos", value);
    rbusValue_Release(value);

    err = rbusMethod_Invoke(rbus_handle,MQTT_PUBLISH_PARAM,inParams,&outParams);
    if (err == RBUS_ERROR_SUCCESS)
    {
    	MqttCMInfo("%s: Message published to broker successfully\n",__func__);
    	ret = true;
    }
    else {
    	MqttCMInfo("%s: Message published to broker failed\n",__func__);
    }
    
    rbusObject_Release(inParams);
    rbusObject_Release(outParams);

    return ret;
}

//To fetch mqttcm broker connection status
int mqttcm_conn_getMqttCMConnStatus()
{
	rbusValue_t value = NULL;
	char *status = NULL;
	int ret = 0, rc = 0;

	rc = rbus_get(get_global_rbus_handle(), MQTT_CONNSTATUS_PARAM, &value);

	if(rc == RBUS_ERROR_SUCCESS)
	{
		status = (char *)rbusValue_GetString(value, NULL);
		if(status !=NULL)
		{
			MqttCMInfo("%s: MqttCM connection status fetched is %s\n",__func__, status);
			if(strncmp(status,  "Up", 2) == 0)
			{
				ret = 1;
			}
		}
		else
		{
			MqttCMError("%s: MqttCM connect status is NULL\n",__func__);
		}
	}
	else
	{
		MqttCMError("%s: MqttCM connect status rbus_get failed, rc %d\n",__func__, rc);
	}
	return ret;
}


int mqttcm_conn_process_messages(void *msg, unsigned int mesg_len, bool do_compress, char *topic, char *qos)
{
	int rc;
	int rbus_conn_response;
	bool is_published = false;

	rbus_conn_response = mqttcm_conn_initialization();

	if(!rbus_conn_response)
	{
		MqttCMInfo("%s: MqttCM lib initialization failed\n",__func__);
		return is_published;
	}

	rc = mqttcm_conn_getMqttCMConnStatus();

	if(rc !=0)
	{
		MqttCMInfo("%s: MqttCM connection is Up; Ready for message publishing\n",__func__);
		if(do_compress)
		{
			mqttcm_conn_compress_messages();
		}
		is_published = mqttcm_conn_publish_messages(msg,topic,qos);
	}
	else {
		MqttCMError("%s: MqttCM connection is down; Drop/Wait for connection to up\n",__func__);
	}

	return is_published;
}