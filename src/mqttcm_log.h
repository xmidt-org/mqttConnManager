#ifndef _MQTTCM_LOG_H_
#define _MQTTCM_LOG_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#if ! defined(DEVICE_EXTENDER)
#include <cimplog.h>
#else
#include "rdk_debug.h"
#endif

#define LOGGING_MODULE                     "MQTTCM"
/**
 * @brief Enables or disables debug logs.
 */
#if defined(BUILD_YOCTO) && ! defined(DEVICE_EXTENDER)

#define MqttCMError(...)                   cimplog_error(LOGGING_MODULE, __VA_ARGS__)
#define MqttCMInfo(...)                    cimplog_info(LOGGING_MODULE, __VA_ARGS__)
#define MqttCMDebug(...)                   cimplog_debug(LOGGING_MODULE, __VA_ARGS__)

#elif defined(BUILD_YOCTO) && defined(DEVICE_EXTENDER)

#define MqttCMError(...) RDK_LOG(RDK_LOG_ERROR,"LOG.RDK.MQTTCM", __VA_ARGS__);
#define MqttCMInfo(...) RDK_LOG(RDK_LOG_INFO,"LOG.RDK.MQTTCM", __VA_ARGS__);
#define MqttCMDebug(...) RDK_LOG(RDK_LOG_DEBUG,"LOG.RDK.MQTTCM", __VA_ARGS__);

#else

#define MqttCMError(...)        printf(__VA_ARGS__)
#define MqttCMInfo(...)         printf(__VA_ARGS__)
#define MqttCMDebug(...)        printf(__VA_ARGS__)

#endif


#endif /* _MQTTCM_LOG_H_ */
