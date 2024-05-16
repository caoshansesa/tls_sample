cmake_minimum_required(VERSION 3.5)
project(TLSProject)

# Create executables for the client and server
add_executable(tls_client client.cpp)
# add_executable(tls_server server.cpp)

# mbedTLS manual configuration
  set(MBEDTLS_LIB_DIR /home/sesa436951/Desktop/NSB_mbedtls/mbedtls/build/library)
  set(MBEDTLS_INCLUDE_DIR /home/sesa436951/Desktop/NSB_mbedtls/mbedtls/include)
  target_include_directories(tls_client PUBLIC ${MBEDTLS_INCLUDE_DIR})
  target_link_libraries(tls_client PUBLIC
    ${MBEDTLS_LIB_DIR}/libmbedtls.a
    ${MBEDTLS_LIB_DIR}/libmbedcrypto.a
    ${MBEDTLS_LIB_DIR}/libmbedx509.a)

  # set(MBEDTLS_LIB_DIR /home/sesa436951/Desktop/NSB_mbedtls/mbedtls/build/library)
  # set(MBEDTLS_INCLUDE_DIR /home/sesa436951/Desktop/NSB_mbedtls/mbedtls/include)
  # target_include_directories(tls_server PUBLIC ${MBEDTLS_INCLUDE_DIR})
  # target_link_libraries(tls_server PUBLIC
  #   ${MBEDTLS_LIB_DIR}/libmbedtls.a
  #   ${MBEDTLS_LIB_DIR}/libmbedcrypto.a
  #   ${MBEDTLS_LIB_DIR}/libmbedx509.a)
