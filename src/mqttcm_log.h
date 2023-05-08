#ifndef _MQTTCM_LOG_H_
#define _MQTTCM_LOG_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#if ! defined(DEVICE_EXTENDER)
#include <cimplog.h>
#endif

#define MQTTCM_LOGGING_MODULE                     "MQTTCM"
/**
 * @brief Enables or disables debug logs.
 */
#if defined(BUILD_YOCTO) && ! defined(DEVICE_EXTENDER)

#define MQTTCM_RDK_LOGGING_MODULE                 "LOG.RDK.MQTTCM"

#define MqttCMError(...)        __cimplog_rdk_generic(MQTTCM_RDK_LOGGING_MODULE, MQTTCM_LOGGING_MODULE, LEVEL_ERROR, __VA_ARGS__)
#define MqttCMInfo(...)         __cimplog_rdk_generic(MQTTCM_RDK_LOGGING_MODULE, MQTTCM_LOGGING_MODULE, LEVEL_INFO, __VA_ARGS__)
#define MqttCMDebug(...)        __cimplog_rdk_generic(MQTTCM_RDK_LOGGING_MODULE, MQTTCM_LOGGING_MODULE, LEVEL_DEBUG, __VA_ARGS__)

#else

#define MqttCMError(...)        printf(__VA_ARGS__)
#define MqttCMInfo(...)         printf(__VA_ARGS__)
#define MqttCMDebug(...)        printf(__VA_ARGS__)

#endif


#endif /* _MQTTCM_LOG_H_ */
