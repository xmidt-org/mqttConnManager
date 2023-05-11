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
#ifndef __MQTTCMGENERIC_H__
#define __MQTTCMGENERIC_H__

#include <stdint.h>

/***!!!! NOTE: This file includes Device specific override functions. Mock implementations are added in mqttcm_generic.c. Actual implementation need to be provided by platform specific code. !!!!***/

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
int Get_Mqtt_LocationId( char *pString);
char* Get_Mqtt_ClientId();
int Get_Mqtt_Broker( char *pString);
int Get_Mqtt_Port( char *pString);
int rbus_GetValueFromDB( char* paramName, char** paramValue);
int rbus_StoreValueIntoDB(char *paramName, char *value);
#endif
