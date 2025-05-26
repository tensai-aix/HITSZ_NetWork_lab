cmake_minimum_required(VERSION 3.0.0)
project(net VERSION 0.1.0)

# Add extra source files here if any
set(EXTRA_FILE 
    
)

if(WIN32)
    set(PCAP wpcap)
else()
    set(PCAP pcap)
endif()

set(HTTP_RESOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/app/resource)

add_compile_options(-Wall -g)
# set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/test) 
include_directories(./include ./Npcap/Include)
link_directories(./Npcap/Lib ./Npcap/Lib/x64)
aux_source_directory(./src DIR_SRCS)

add_executable(icmp_server
    ${DIR_SRCS}
    ./app/icmp_server.c
)
target_link_libraries(icmp_server ${PCAP})
target_compile_definitions(icmp_server PRIVATE ICMP PING)

add_executable(ip_server
    ${DIR_SRCS}
    ./app/ip_server.c
)
target_link_libraries(ip_server ${PCAP})
target_compile_definitions(ip_server PRIVATE ICMP IP_SER)

add_executable(udp_server
    ${DIR_SRCS}
    ./app/udp_server.c
)
target_link_libraries(udp_server ${PCAP})
target_compile_definitions(udp_server PRIVATE ICMP UDP)

add_executable(tcp_server
    ${DIR_SRCS}
    ./app/tcp_server.c
)
target_link_libraries(tcp_server ${PCAP})
target_compile_definitions(tcp_server PRIVATE ICMP TCP)

add_executable(web_server
    ${DIR_SRCS}
    ./app/web_server.c
)
target_link_libraries(web_server ${PCAP})
target_compile_definitions(web_server PUBLIC HTTP_RESOURCE_DIR="${HTTP_RESOURCE_DIR}" ICMP TCP)

set(TEST_FIX_SOURCE 
    testing/faker/driver.c 
    testing/global.c
    src/net.c
    src/buf.c
    src/map.c
    src/tcp.c
    src/utils.c
)

# aux_source_directory(./testing DIR_TEST)
add_executable(eth_in 
    testing/eth_in.c
    src/ethernet.c
    testing/faker/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(eth_in ${PCAP})
target_compile_definitions(eth_in PUBLIC TEST)

add_executable(eth_out
    testing/eth_out.c
    src/ethernet.c
    testing/faker/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(eth_out ${PCAP})
target_compile_definitions(eth_out PUBLIC TEST)

add_executable(arp_test
    testing/arp_test.c
    src/ethernet.c
    src/arp.c
    testing/faker/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(arp_test ${PCAP})
target_compile_definitions(arp_test PUBLIC TEST)

add_executable(ip_test
    testing/ip_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(ip_test ${PCAP})
target_compile_definitions(ip_test PUBLIC TEST ICMP UDP)

add_executable(ip_frag_test
    testing/ip_frag_test.c
    testing/faker/arp.c
    src/ethernet.c
    src/ip.c
    testing/faker/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(ip_frag_test ${PCAP})
target_compile_definitions(ip_frag_test PUBLIC TEST ICMP UDP)

add_executable(icmp_test
    testing/icmp_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    src/icmp.c
    testing/faker/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(icmp_test ${PCAP})
target_compile_definitions(icmp_test PUBLIC TEST ICMP UDP)

add_executable(udp_test
    testing/udp_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    src/icmp.c
    src/udp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(udp_test ${PCAP})
target_compile_definitions(udp_test PUBLIC TEST ICMP UDP)

add_executable(tcp_test
    testing/tcp_test.c
    src/ethernet.c
    src/arp.c
    src/ip.c
    src/icmp.c
    src/tcp.c
    ${TEST_FIX_SOURCE}
    ${EXTRA_FILE}
)
target_link_libraries(tcp_test ${PCAP})
target_compile_definitions(tcp_test PUBLIC TEST ICMP TCP)

enable_testing()

add_test(
    NAME eth_in 
    COMMAND $<TARGET_FILE:eth_in> ${CMAKE_CURRENT_LIST_DIR}/testing/data/eth_in
)

add_test(
    NAME eth_out
    COMMAND $<TARGET_FILE:eth_out> ${CMAKE_CURRENT_LIST_DIR}/testing/data/eth_out
)

add_test(
    NAME arp_test
    COMMAND $<TARGET_FILE:arp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/arp_test
)

add_test(
    NAME ip_test
    COMMAND $<TARGET_FILE:ip_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/ip_test
)

add_test(
    NAME ip_frag_test
    COMMAND $<TARGET_FILE:ip_frag_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/ip_frag_test
)

add_test(
    NAME icmp_test
    COMMAND $<TARGET_FILE:icmp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/icmp_test
)

add_test(
    NAME udp_test
    COMMAND $<TARGET_FILE:udp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/udp_test
)

add_test(
    NAME tcp_test
    COMMAND $<TARGET_FILE:tcp_test> ${CMAKE_CURRENT_LIST_DIR}/testing/data/tcp_test
)

message("Executable files is in ${EXECUTABLE_OUTPUT_PATH}.")
