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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <rbus/rbus.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <CUnit/Basic.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <assert.h>
#include <mosquitto.h>
#include "../src/mqttcm_connect.h"
#include "../src/mqttcm_generic.h"
#include "../src/mqttcm_generic.h"
#include "../src/mqttcm_log.h"
#include "../src/mqttcm_privilege.h"
#include "../src/mqttcm_webcfg.h"

#define UNUSED(x) (void)(x)
//typedef struct mosquitto mosq1;

/*----------------------------------------------------------------------------*/
/*                                   Mocks                                    */
/*----------------------------------------------------------------------------*/

int mosquitto_disconnect(struct mosquitto *mosq)
{
	UNUSED(mosq);
	function_called();
	return (int) mock();

}

const char *mosquitto_reason_string(int reason_code)
{
	UNUSED(reason_code);
	function_called();
	return (char*) (intptr_t)mock();
}	

int mosquitto_lib_init(void)
{
	function_called();
	return (int) mock();
}

struct mosquitto *mosquitto_new(const char *id, bool clean_start, void *userdata)
{
	UNUSED(id); UNUSED(clean_start); UNUSED(userdata);
	function_called();
	return (struct mosquitto*) (intptr_t)mock();
}	

int mosquitto_int_option(struct mosquitto *mosq, enum mosq_opt_t option, int value)
{
	UNUSED(mosq); UNUSED(option); UNUSED(value);
	function_called();
	return (int) mock();
}

void mosquitto_destroy(struct mosquitto *mosq)
{
	UNUSED(mosq);
	function_called();
}

int mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char *capath, const char *certfile, const char *keyfile, int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
	UNUSED(mosq); UNUSED(cafile); UNUSED(capath); UNUSED(certfile); UNUSED(keyfile);
	function_called();
	return (int) mock();
}	

int mosquitto_tls_opts_set(struct mosquitto *mosq, int cert_reqs, const char *tls_version, const char *ciphers)
{			
	UNUSED(mosq); UNUSED(cert_reqs); UNUSED(tls_version); UNUSED(ciphers);
	function_called();
	return (int) mock();
}

void mosquitto_connect_v5_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int, int, const mosquitto_property *))
{
	UNUSED(mosq);
	function_called();
}

void mosquitto_disconnect_v5_callback_set(struct mosquitto *mosq, void (*on_disconnect)(struct mosquitto *, void *, int, const mosquitto_property *))
{
	UNUSED(mosq);
	function_called();
}

void mosquitto_subscribe_v5_callback_set(struct mosquitto *mosq, void (*on_subscribe)(struct mosquitto *, void *, int, int, const int *, const mosquitto_property *props))
{
	function_called();
}

void mosquitto_message_v5_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *, const mosquitto_property *props))
{
	UNUSED(mosq);
	function_called();
}

void mosquitto_publish_v5_callback_set(struct mosquitto *mosq, void (*on_publish)(struct mosquitto *, void *, int, int, const mosquitto_property *props))
{
	UNUSED(mosq);
	function_called();
}

int mosquitto_connect_bind_v5(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address, const mosquitto_property *properties)
{
	UNUSED(mosq);
	function_called();
	return (int) mock();
}

int mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets)
{
	UNUSED(mosq); UNUSED(timeout); UNUSED(max_packets);
	function_called();
	return (int) mock();
}

int mosquitto_lib_cleanup(void)
{
	function_called();
	return (int) mock();
}	

int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
	UNUSED(mosq); UNUSED(mid); UNUSED(sub); UNUSED(qos);
	function_called();
	return (int) mock();
}

const char *mosquitto_strerror(int mosq_errno)
{
	UNUSED(mosq_errno);
	function_called();
	return (char*) (intptr_t)mock();
}

const char *mosquitto_connack_string(int connack_code)
{
	UNUSED(connack_code);
	function_called();
	return (char*) (intptr_t)mock();
}

int mosquitto_property_add_string_pair(mosquitto_property **proplist, int identifier, const char *name, const char *value)
{
	UNUSED(proplist); UNUSED(identifier); UNUSED(name); UNUSED(value);
	function_called();
	return (int) mock();
}

int mosquitto_publish_v5(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain, const mosquitto_property *properties)
{
	UNUSED(mosq); UNUSED(mid); UNUSED(topic); UNUSED(payloadlen); UNUSED(payload); UNUSED(qos); UNUSED(retain); UNUSED(properties);
	function_called();
	return (int) mock();	
}

int mosquitto_loop(struct mosquitto *mosq, int timeout, int max_packets)
{
	UNUSED(mosq); UNUSED(timeout); UNUSED(max_packets);
	function_called();
	return (int) mock();
}

void mosquitto_property_free_all(mosquitto_property **property)
{
	UNUSED(property);
	function_called();
}

/*----------------------------------------------------------------------------*/
/*                                   Tests                                    */
/*----------------------------------------------------------------------------*/
void test_mqttCMConnectBroker()
{ 	
 	bool result = false;

 	// Test 1 - mosquitto_new fails returns NULL
 	mqttCMRbusInit("mqttConnManager");
    	regMqttDataModel();

    	will_return (mosquitto_lib_init, 0);
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, NULL);
  	expect_function_call (mosquitto_new);

  	result = mqttCMConnectBroker();
  	assert_true(result);
  	printf("---------------Tested mqttCMConnectBroker 1---------------\n");

  	/*// Test 2 - get tls cert files Failed
 	struct mosquitto *mosq1 = NULL;

 	will_return (mosquitto_lib_init, 0);
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, &mosq1);
  	expect_function_call (mosquitto_new);

  	will_return (mosquitto_int_option, 0);
  	expect_function_call (mosquitto_int_option);

  	expect_function_call(mosquitto_destroy);

  	will_return (mosquitto_new, NULL);
  	expect_function_call (mosquitto_new);

  	result = mqttCMConnectBroker();
  	assert_true(result);  	
  	printf("---------------Tested mqttCMConnectBroker 2---------------\n");*/

  	// Test 3 - mosquitto_tls_set Failed
  	struct mosquitto *mosq2 = NULL;
  	//char* filepath = "/tmp/.mqttconfig"; 
	FILE* file1 = fopen(MQTT_CONFIG_FILE, "w"); 
 	/*char tmpfilename1[20];
    	snprintf(tmpfilename1, 20 , "%s.XXXXXX", ".mqttconfig");
    	mkstemp(tmpfilename1);
    	FILE *file1 = fopen(tmpfilename1, "w"); */
    	if(NULL != file1) {
    		fputs("CA_FILE_PATH=/xxx/yyy/zzzzzz/plume_ca.pem\n", file1);
    		fputs("CERT_FILE_PATH=/aaa/bbbbb/client.pem\n", file1);
    		fputs("KEY_FILE_PATH=/bbb/cccc/mqttcm/jlyauhtie.mvf\n", file1);
    		fclose(file1);
    		//rewind(file1);
    	}
    	else {
    		printf("------Failed to create file1-------\n");	
    	}
    	//rename(tmpfilename1,".mqttconfig");

    	will_return (mosquitto_lib_init, 0);
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, &mosq2);
  	expect_function_call (mosquitto_new);

  	will_return (mosquitto_int_option, 0);
  	expect_function_call (mosquitto_int_option);

   	will_return (mosquitto_tls_set, 1);
  	expect_function_call (mosquitto_tls_set);

  	will_return (mosquitto_strerror, "Out of memory.");
  	expect_function_call (mosquitto_strerror);

  	expect_function_call(mosquitto_destroy);

  	will_return (mosquitto_new, NULL);
  	expect_function_call (mosquitto_new);

  	result = mqttCMConnectBroker();
  	assert_true(result);  	
  	printf("---------------Tested mqttCMConnectBroker 3---------------\n");

  	//Test 4 - mosquitto_tls_opts_set Failed
  	struct mosquitto *mosq3 = NULL;
  	will_return (mosquitto_lib_init, 0);
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, &mosq3);
  	expect_function_call (mosquitto_new);

  	will_return (mosquitto_int_option, 0);
  	expect_function_call (mosquitto_int_option);

   	will_return (mosquitto_tls_set, 0);
  	expect_function_call (mosquitto_tls_set);

  	will_return (mosquitto_tls_opts_set, 1);
  	expect_function_call (mosquitto_tls_opts_set);

  	will_return (mosquitto_strerror, "Out of memory.");
  	expect_function_call (mosquitto_strerror);

  	expect_function_call(mosquitto_destroy);

  	will_return (mosquitto_new, NULL);
  	expect_function_call (mosquitto_new);

  	result = mqttCMConnectBroker();
  	assert_true(result);  	
  	printf("---------------Tested mqttCMConnectBroker 4---------------\n");

    	//Test 5 - Proceed with connect MQTT broker, loop forever failed
  	struct mosquitto *mosq4 = NULL;
  	//char* devicePropsFile = "/tmp/device.properties"; 
	FILE* file2 = fopen(DEVICE_PROPS_FILE, "w");
  	/*char tmpfilename2[20];
    	snprintf(tmpfilename2, 20 , "%s.XXXXXX", "device.properties");
    	mkstemp(tmpfilename2);
    	FILE *file2 = fopen(tmpfilename2, "w"); */ 
        const char* content = "WEBCONFIG_INTERFACE=eth0\n";
       if(NULL != file2) {
        	fputs(content, file2);
        	fclose(file2);
       }
       else {
        	printf("-------Failed to create file2----------\n");
       }
	//rename(tmpfilename2,"device.properties");
  	will_return (mosquitto_lib_init, 0);
  	
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, &mosq4);
  	expect_function_call (mosquitto_new);

  	will_return (mosquitto_int_option, 0);
  	expect_function_call (mosquitto_int_option);

   	will_return (mosquitto_tls_set, 0);
  	expect_function_call (mosquitto_tls_set);

  	will_return (mosquitto_tls_opts_set, 0);
  	expect_function_call (mosquitto_tls_opts_set);

  	expect_function_call (mosquitto_connect_v5_callback_set);
  	expect_function_call (mosquitto_disconnect_v5_callback_set);
  	expect_function_call (mosquitto_subscribe_v5_callback_set);
  	expect_function_call (mosquitto_message_v5_callback_set);
  	expect_function_call (mosquitto_publish_v5_callback_set);

  	will_return (mosquitto_connect_bind_v5, 0);
  	expect_function_call (mosquitto_connect_bind_v5);

  	will_return (mosquitto_loop_forever, 1);
  	expect_function_call (mosquitto_loop_forever);

  	expect_function_call(mosquitto_destroy);

  	will_return (mosquitto_strerror, "Out of memory.");
  	expect_function_call (mosquitto_strerror);

  	result = mqttCMConnectBroker();
  	assert_true(result);  	
  	printf("---------------Tested mqttCMConnectBroker 5---------------\n");

  	//Test 6 - MQTT connect broker success 

  	 will_return (mosquitto_lib_init, 0);
  	expect_function_call (mosquitto_lib_init);

  	will_return (mosquitto_new, &mosq4);
  	expect_function_call (mosquitto_new);

  	will_return (mosquitto_int_option, 0);
  	expect_function_call (mosquitto_int_option);

   	will_return (mosquitto_tls_set, 0);
  	expect_function_call (mosquitto_tls_set);

  	will_return (mosquitto_tls_opts_set, 0);
  	expect_function_call (mosquitto_tls_opts_set);

  	expect_function_call (mosquitto_connect_v5_callback_set);
  	expect_function_call (mosquitto_disconnect_v5_callback_set);
  	expect_function_call (mosquitto_subscribe_v5_callback_set);
  	expect_function_call (mosquitto_message_v5_callback_set);
  	expect_function_call (mosquitto_publish_v5_callback_set);

  	will_return (mosquitto_connect_bind_v5, 0);
  	expect_function_call (mosquitto_connect_bind_v5);

  	will_return (mosquitto_loop_forever, 0);
  	expect_function_call (mosquitto_loop_forever);

   	expect_function_call(mosquitto_destroy);

   	will_return (mosquitto_lib_cleanup, 0);
  	expect_function_call (mosquitto_lib_cleanup);

  	result = mqttCMConnectBroker();
  	assert_false(result);  	
  	printf("---------------Tested mqttCMConnectBroker 6---------------\n");

  	//remove("/tmp/.mqttconfig");
  	//remove("/tmp/device.properties");
    	mqttCMRbus_Uninit();
 }

 void test_mqtt_subscribe1()
 {
 	int result = 0;

 	//Test 1 - comp & topic NULL
 	result = mqtt_subscribe(NULL, NULL);
 	assert_int_equal(result, 1);
 	printf("---------------Tested mqtt_subscribe 1---------------\n");

 	//Test 2 - Add to subscribe List & compName = Component1
 	result = mqtt_subscribe("Component1", "Topic1");
 	assert_int_equal(result,0);
 	printf("---------------Tested mqtt_subscribe 2---------------\n");

  	//Test 3 - mosquitto_subscribe failed
  	char comp[] = "webconfig";
  	char topic[] = "x/to/xxxxxxxxxxxx/webconfig";
  	char *compName = strdup(comp);
  	char *topicName= strdup(topic);

  	will_return (mosquitto_subscribe, 1);
  	expect_function_call (mosquitto_subscribe);

  	will_return (mosquitto_strerror, "Out of memory.");
  	expect_function_call (mosquitto_strerror);

 	result = mqtt_subscribe(compName, topicName);
 	assert_int_equal(result,1);
 	printf("---------------Tested mqtt_subscribe 3---------------\n");

 	//Test 4 - mosquitto_subscribe success
 	will_return (mosquitto_subscribe, 0);
  	expect_function_call (mosquitto_subscribe);

  	result = mqtt_subscribe(compName, topicName);
 	assert_int_equal(result,0);
 	printf("---------------Tested mqtt_subscribe 4---------------\n");

 	//Test 5 - resubscribe of the same component again
  	result = mqtt_subscribe(compName, topicName);
 	assert_int_equal(result,0);
 	printf("---------------Tested mqtt_subscribe 5---------------\n");
}	

void test_mosquittoTriggerDisconnect()
{
	will_return (mosquitto_disconnect, 0);
  	expect_function_call (mosquitto_disconnect);
  	mosquittoTriggerDisconnect();
  	printf("---------------Tested mosquittoTriggerDisconnect---------------\n");
}

void test_on_disconnect()
{
 	will_return(mosquitto_reason_string, "Disconnect with Will Message");
 	expect_function_call(mosquitto_reason_string);
 	on_disconnect(NULL, NULL, 0, NULL);
 	printf("---------------Tested on_disconnect---------------\n");
}

void test_mosquittoTriggerDisconnect_skip()
{
	//skipping this reconnect request
  	mosquittoTriggerDisconnect();
  	printf("---------------Tested mosquittoTriggerDisconnect_skip---------------\n");
}

void test_on_connect()
{
	// Test 1 - Broker unavailable (reason code non zero)
	will_return(mosquitto_connack_string, "Connection Refused: broker unavailable.");
 	expect_function_call(mosquitto_connack_string);

 	will_return (mosquitto_disconnect, 0);
  	expect_function_call (mosquitto_disconnect);

 	on_connect(NULL, NULL, 3, 0, NULL);
 	printf("---------------Tested on_connect 1---------------\n");

 	// Test 2 - mqtt reconnection case (reconnectFlag '1')
 	will_return(mosquitto_connack_string, "Connection Accepted.");
 	expect_function_call(mosquitto_connack_string);

 	will_return (mosquitto_subscribe, 0);
  	expect_function_call (mosquitto_subscribe);

 	on_connect(NULL, NULL, 0, 0, NULL);	
 	printf("---------------Tested on_connect 2---------------\n");

 	//Test 3 - crash or process restart case (reconnectFlag '0')
 	remove(MQTT_SUBSCRIBER_FILE);
 	AddSubscribeTopicToFile("webcfg", "x/to/xxxxxxxxxxxx/webcfg");
 	will_return(mosquitto_connack_string, "Connection Accepted.");
 	expect_function_call(mosquitto_connack_string);

 	on_connect(NULL, NULL, 0, 0, NULL);
 	printf("---------------Tested on_connect 3---------------\n");	
}

void test_on_subscribe()
{
	// Test 1 - topic NULL
        will_return (mosquitto_disconnect, 0);
  	expect_function_call (mosquitto_disconnect);

  	int g_qos1 = 10;
	on_subscribe(NULL, NULL, 1, 1, &g_qos1, NULL);
	printf("---------------Tested on_subscribe 1---------------\n");

	// Test 2 - topic valid
	int g_qos2 = 1;
  	UpdateSubscriptionIdToList("webconfig", 1);	
	on_subscribe(NULL, NULL, 1, 1, &g_qos2, NULL);
	printf("---------------Tested on_subscribe 2---------------\n");
}

void test_mqtt_subscribe2()
{
	// Test - webcfg_subscribed = 1
	int result = mqtt_subscribe("Component2", "Topic2");
	assert_int_equal(result,0);
	printf("---------------Tested mqtt_subscribe2---------------\n");
}

void test_publish_notify_mqtt()
{
	// Test 1 - mosquitto_property_add_string_pair & mosquitto_publish_v5 failed
	will_return(mosquitto_property_add_string_pair, 1);
 	expect_function_call(mosquitto_property_add_string_pair);

 	will_return(mosquitto_publish_v5, 1);
 	expect_function_call(mosquitto_publish_v5);

 	will_return(mosquitto_strerror, "Out of memory.");
 	expect_function_call(mosquitto_strerror);

 	will_return (mosquitto_loop, 0);
  	expect_function_call (mosquitto_loop);

  	expect_function_call(mosquitto_property_free_all);

	publish_notify_mqtt(NULL, NULL, 0);
	printf("---------------Tested test_publish_notify_mqtt 1---------------\n");

	// Test 2 - success
	will_return(mosquitto_property_add_string_pair, 0);
 	expect_function_call(mosquitto_property_add_string_pair);

 	will_return(mosquitto_publish_v5, 0);
 	expect_function_call(mosquitto_publish_v5);

 	will_return (mosquitto_loop, 0);
  	expect_function_call (mosquitto_loop);

  	expect_function_call(mosquitto_property_free_all);

	publish_notify_mqtt(NULL, NULL, 0);
	printf("---------------Tested test_publish_notify_mqtt 2---------------\n");	
}

void test_on_message()
{
	//Test 1 - message is NULL
	on_message(NULL, NULL, NULL, NULL);
	printf("---------------Tested on_mes2sage 1---------------\n");

	//Test 2 - message payload is NULL
	char topic1[] = "Topic1";
	struct mosquitto_message mosq_msg1;
	mosq_msg1.mid = 1;
	mosq_msg1.topic = strdup(topic1);
	mosq_msg1.payload = NULL;
	mosq_msg1.payloadlen = 0;
	mosq_msg1.qos = 0;
	mosq_msg1.retain = true;

	on_message(NULL, NULL, &mosq_msg1, NULL);
	printf("---------------Tested on_message 2---------------\n");

	// Test2 - Couldn't find topic
	char topic2[] = "Topic1";
	char payload2[] = "HTTP/1.1 200 OK";
	struct mosquitto_message mosq_msg2;
	mosq_msg1.mid = 1;
	mosq_msg2.topic = strdup(topic2);
	mosq_msg2.payload = strdup(payload2);
	mosq_msg2.payloadlen = 6017;
	mosq_msg2.qos = 0;
	mosq_msg2.retain = true;

	on_message(NULL, NULL, &mosq_msg2, NULL);
	printf("---------------Tested on_message 3---------------\n");

	//Test 3 - Component not found
	char topic3[] = "Topic3";
	char payload3[] = "HTTP/1.1 200 OK";
	struct mosquitto_message mosq_msg3;
	mosq_msg3.mid = 1;
	mosq_msg3.topic = strdup(topic3);
	mosq_msg3.payload = strdup(payload3);
	mosq_msg3.payloadlen = 6017;
	mosq_msg3.qos = 0;
	mosq_msg3.retain = true;

	on_message(NULL, NULL, &mosq_msg3, NULL);
	printf("---------------Tested on_message 4---------------\n");

	//Test 4 - Component "webconfig"
	char topic4[] = "x/to/xxxxxxxxxxxx/webconfig";
	char payload4[] = "HTTP/1.1 200 OK";
	struct mosquitto_message mosq_msg4;
	mosq_msg4.mid = 1;
	mosq_msg4.topic = strdup(topic4);
	mosq_msg4.payload = strdup(payload4);
	mosq_msg4.payloadlen = 6017;
	mosq_msg4.qos = 0;
	mosq_msg4.retain = true;

	will_return(mosquitto_property_add_string_pair, 0);
 	expect_function_call(mosquitto_property_add_string_pair);

 	will_return(mosquitto_publish_v5, 0);
 	expect_function_call(mosquitto_publish_v5);

 	will_return (mosquitto_loop, 0);
  	expect_function_call (mosquitto_loop);

  	expect_function_call(mosquitto_property_free_all);

	on_message(NULL, NULL, &mosq_msg4, NULL);
	printf("---------------Tested on_message 4---------------\n");
}

void test_on_publish()
{
	on_publish(NULL, NULL, 1, 0, NULL);
	printf("---------------Tested on_publish---------------\n");
}	

 /*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
        const struct CMUnitTest tests[] = {
        	cmocka_unit_test(test_mqttCMConnectBroker),
        	cmocka_unit_test(test_mqtt_subscribe1),
        	cmocka_unit_test(test_on_message),
        	cmocka_unit_test(test_mosquittoTriggerDisconnect),
        	cmocka_unit_test(test_on_disconnect),
        	cmocka_unit_test(test_mosquittoTriggerDisconnect_skip),
        	cmocka_unit_test(test_on_connect),
        	cmocka_unit_test(test_on_subscribe),
        	cmocka_unit_test(test_mqtt_subscribe2),
        	cmocka_unit_test(test_publish_notify_mqtt),
        	cmocka_unit_test(test_on_publish)
        	};
     return cmocka_run_group_tests(tests, NULL, 0);
}	
