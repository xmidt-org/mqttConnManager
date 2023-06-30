/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <rbus.h>
#include "mqttcm_generic.h"
#include "mqttcm_log.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define UNUSED(x) (void )(x)
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
#ifndef MQTTCM_SUPPORT
int __attribute__((weak)) Get_Mqtt_LocationId( char *pString);
int __attribute__((weak)) Get_Mqtt_Broker( char *pString);
int __attribute__((weak)) Get_Mqtt_Port( char *pString);
char* __attribute__((weak)) Get_Mqtt_ClientId();
int __attribute__((weak)) rbus_GetValueFromDB( char* paramName, char** paramValue);
int __attribute__((weak)) rbus_StoreValueIntoDB(char *paramName, char *value);
#endif
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
#ifndef MQTTCM_SUPPORT
int Get_Mqtt_LocationId( char *pString)
{
    MqttCMInfo("Inside Get_Mqtt_LocationId weak function.\n");
    strcpy(pString, "12345678927e9a892c670333");
    return 0;
}
char* Get_Mqtt_ClientId()
{
    MqttCMInfo("Inside Get_Mqtt_ClientId weak function.\n");
    return "123456789012";
}
int Get_Mqtt_Broker( char *pString)
{
    MqttCMInfo("Inside Get_Mqtt_Broker weak function.\n");
    strcpy(pString, "localhost");
    return 0;
}
int Get_Mqtt_Port( char *pString)
{
    MqttCMInfo("Inside Get_Mqtt_Port weak function.\n");
    strcpy(pString, "123");
    return 0;
}
int rbus_GetValueFromDB( char* paramName, char** paramValue)
{
	MqttCMInfo("Inside rbus_GetValueFromDB weak fn\n");
	UNUSED(paramName);
	UNUSED(paramValue);
	return 0;
}

int rbus_StoreValueIntoDB(char *paramName, char *value)
{
	MqttCMInfo("Inside rbus_StoreValueIntoDB weak fn\n");
	UNUSED(paramName);
	UNUSED(value);
	return 0;
}
#endif
