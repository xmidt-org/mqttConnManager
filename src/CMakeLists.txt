#   Copyright 2023 Comcast Cable Communications Management, LLC
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set(PROJ_WEBCFG mqttConnManager)

set(HEADERS mqttcm_connect.h mqttcm_log.h mqttcm_privilege.h mqttcm_generic.h mqttcm_webcfg.h)
set(SOURCES main.c mqttcm_connect.c mqttcm_privilege.c mqttcm_generic.c mqttcm_webcfg.c)

if (NOT DEVICE_EXTENDER)
set(COMMON_LIBS ${COMMON_LIBS} -lcimplog)
else ()
add_definitions(-DDEVICE_EXTENDER)
endif()

add_executable(mqttConnManager ${SOURCES} ${HEADERS})
set_property(TARGET mqttConnManager PROPERTY C_STANDARD 99)
set(COMMON_LIBS -lpthread -lrbus -lmosquitto -luuid -lcjson)

target_link_libraries (mqttConnManager ${CMAKE_THREAD_LIBS_INIT} ${COMMON_LIBS})
install (TARGETS mqttConnManager DESTINATION bin)
