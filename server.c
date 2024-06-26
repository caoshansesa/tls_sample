#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <stdio.h>
#include <string.h>

int main()
{
    int ret;
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *pers = "ssl_server";
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the RNG
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        printf("mbedtls_ctr_drbg_seed failed\n");
        return 1;
    }

    // Load certificates
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Setup listening TCP socket
    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf("mbedtls_net_bind failed\n");
        return 1;
    }

    // Wait for a connection
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
    {
        printf("mbedtls_net_accept failed\n");
        return 1;
    }

    // Setup SSL
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        printf("mbedtls_ssl_setup failed\n");
        return 1;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // Handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("mbedtls_ssl_handshake failed\n");
            return 1;
        }
    }

    printf("TLS handshake succeeded\n");

    // Cleanup
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
