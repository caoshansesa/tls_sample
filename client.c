#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include <arpa/inet.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <thread>
#include <time.h>

#define NOK -1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SERVER_PORT 802
#define SERVER_IP "192.168.10.10"

int main()
{

    int sock;
    struct sockaddr_in server_addr;
    ssize_t bytes_received;
    
    // Create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error creating socket");
        return -1;
    }
    
    // Set up the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(sock);
        return -1;
    }

    char KEY_PATH[] = "../role_based_cert/client.key";
    char CERT_PATH[] = "../role_based_cert/client.crt";
    char CA_CERT_PATH[] = "../role_based_cert/ca.crt";
    mbedtls_ssl_config mbed_ssl_conf_;
    mbedtls_entropy_context mbed_ssl_entropy_;
    mbedtls_ctr_drbg_context mbed_ssl_ctr_drbg_;
    mbedtls_net_context server_fd;
    // Create a local ssl context

    mbedtls_entropy_init(&mbed_ssl_entropy_);
    mbedtls_ctr_drbg_init(&mbed_ssl_ctr_drbg_);
    mbedtls_ssl_config_init(&mbed_ssl_conf_);
    mbedtls_net_init(&server_fd);

    const char *pers = "ssl_client";
    int ret;

    if ((ret = mbedtls_ctr_drbg_seed(&mbed_ssl_ctr_drbg_, mbedtls_entropy_func, &mbed_ssl_entropy_,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed in mbedtls_ctr_drbg_seed: %d\n", ret);
        return NOK;
    }

    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;

    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

    // Load the trusted CA
    ret = mbedtls_x509_crt_parse_file(&cacert, "../../role_based_cert/ca.crt");
    if (ret != 0)
    {
        printf("Failed to load CA certificate\n");
        return NOK;
    }

    if ((ret = mbedtls_x509_crt_parse_file(&clicert, "../../role_based_cert/client.crt")) != 0)
    {
        printf("Failed loading client cert\n");
        return NOK;
    }
    if ((ret = mbedtls_pk_parse_keyfile(&pkey, "../../role_based_cert/client.key", NULL)) != 0)
    {
        printf("Failed loading key\n");
        return NOK;
    }

    if ((ret = mbedtls_ssl_config_defaults(&mbed_ssl_conf_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf("Failed in mbedtls_ssl_config_defaults: %d\n", ret);
        return NOK;
    }

    mbedtls_ssl_conf_authmode(&mbed_ssl_conf_, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&mbed_ssl_conf_, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&mbed_ssl_conf_, &clicert, &pkey);



    // mbedtls_net_connect(&server_fd, "192.168.10.10", "802", MBEDTLS_NET_PROTO_TCP);
    server_fd.fd = sock;

    mbedtls_ssl_conf_rng(&mbed_ssl_conf_, mbedtls_ctr_drbg_random, &mbed_ssl_ctr_drbg_);

    char err_buf[100];
    mbedtls_ssl_context mbed_ssl_contxt_;
    mbedtls_ssl_init(&mbed_ssl_contxt_);
    // Create a mbedtls_fd structure
    mbedtls_ssl_init(&mbed_ssl_contxt_);
    mbedtls_ssl_config *conf_ = &mbed_ssl_conf_;
    if ((mbedtls_ssl_setup(&mbed_ssl_contxt_, conf_)) != 0)
    {
        printf("Failed in mbedtls_ssl_setup\n");
        return NOK;
    }

    mbedtls_ssl_set_bio(&mbed_ssl_contxt_, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // Perform the SSL handshake
    int i = 0;
    int ssl_connect_ret = mbedtls_ssl_handshake(&mbed_ssl_contxt_);
    while (ssl_connect_ret != 0 && i < 5)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        mbedtls_strerror(ssl_connect_ret, err_buf, 100);
        ssl_connect_ret = mbedtls_ssl_handshake(&mbed_ssl_contxt_);
        i++;
    }
    if (i == 5)
    {
        printf("tried 5 times, exit now\n");
        return NOK; // exit after 5 times connect tries
    }

    const char *hello = "Hello\n\n\n\n\n\n\n";
    ret = mbedtls_ssl_write(&mbed_ssl_contxt_, (const unsigned char *)hello, strlen(hello));
    if (ret <= 0)
    {
        printf("write error\n");
    }
}
