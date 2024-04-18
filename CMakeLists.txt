cmake_minimum_required(VERSION 3.0)
project(TLSProject)

# Path to mbedtls library
set(MBEDTLS_PATH "~/Desktop/mbedtls/mbedtls/")

# Include mbedtls
include_directories(${MBEDTLS_PATH}/include)
link_directories(${MBEDTLS_PATH}/library)

# Create executables for the client and server
add_executable(tls_client client.c)
add_executable(tls_server server.c)

# Link with mbedTLS
target_link_libraries(tls_client mbedtls mbedx509 mbedcrypto)
target_link_libraries(tls_server mbedtls mbedx509 mbedcrypto)
