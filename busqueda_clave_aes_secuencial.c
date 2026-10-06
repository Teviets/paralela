/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Ejercicio:   Busqueda secuencial de una clave AES mediante fuerza bruta
 * Descripcion: un unico proceso prueba claves candidatas en orden
 *              y compara el mensaje descifrado con el texto original.
 *
 *              Para fines educativos, la busqueda se limita a
 *              1,048,576 candidatas del espacio de claves de AES.
 *              El cifrado utiliza la interfaz EVP de OpenSSL.
 *              Se mide el tiempo transcurrido durante la busqueda.
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define TOTAL_KEYS (UINT64_C(1) << 20)
#define SECRET_KEY UINT64_C(12345)
#define MESSAGE_LEN 16

/* Texto original de 16 bytes; el cero final no se cifra. */
static const unsigned char message[] = "Puedes lograrlo!";

_Static_assert(
    sizeof(message) - 1 == MESSAGE_LEN,
    "El mensaje debe tener exactamente 16 bytes."
);

/* Muestra el error y termina el programa. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* Construye una clave AES no aleatoria a partir de la candidata. */
static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);

    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)(
            (candidate >> (8 * i)) & UINT64_C(0xFF)
        );
    }
}

/*
 * Cifra o descifra un bloque mediante AES-128-ECB.
 * encrypt = 1: cifrar; encrypt = 0: descifrar.
 * ECB se utiliza para un unico bloque educativo.
 */
static void crypt_block(
    EVP_CIPHER_CTX *ctx,
    uint64_t candidate,
    const unsigned char *input,
    unsigned char *output,
    int encrypt)
{
    unsigned char key[16];
    int written = 0;
    int final_written = 0;

    make_key(candidate, key);

    if (EVP_CipherInit_ex(
            ctx, EVP_aes_128_ecb(), NULL,
            key, NULL, encrypt) != 1) {
        fail("Error al inicializar AES.");
    }

    /* El mensaje ocupa exactamente un bloque, sin relleno. */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        fail("Error al configurar el relleno.");
    }

    if (EVP_CipherUpdate(
            ctx, output, &written,
            input, MESSAGE_LEN) != 1) {
        fail("Error al procesar el bloque.");
    }

    if (EVP_CipherFinal_ex(
            ctx, output + written, &final_written) != 1) {
        fail("Error al finalizar la operacion AES.");
    }

    if (written + final_written != MESSAGE_LEN) {
        fail("Longitud inesperada del resultado.");
    }
}

/* Obtiene el tiempo de un reloj monotono, en segundos. */
static double get_time(void)
{
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        perror("Error al consultar el reloj");
        exit(EXIT_FAILURE);
    }

    return (double)current.tv_sec +
           (double)current.tv_nsec / 1000000000.0;
}

int main(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    unsigned char cipher[
        MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH
    ] = {0};

    unsigned char plain[
        MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH
    ] = {0};

    /*
     * Prepara el mensaje cifrado.
     * SECRET_KEY solo se utiliza para preparar el ejercicio.
     */
    crypt_block(ctx, SECRET_KEY, message, cipher, 1);

    uint64_t found = UINT64_MAX;

    /* La medicion comienza despues de preparar el mensaje. */
    double start = get_time();

    /* Prueba las claves consecutivamente desde cero. */
    for (uint64_t key = 0; key < TOTAL_KEYS; key++) {
        crypt_block(ctx, key, cipher, plain, 0);

        /* Verifica todos los bytes del mensaje conocido. */
        if (memcmp(plain, message, MESSAGE_LEN) == 0) {
            found = key;
            break;
        }
    }

    double elapsed = get_time() - start;

    if (found != UINT64_MAX) {
        printf("Clave encontrada: %" PRIu64 "\n", found);
        printf("Mensaje: ");
        fwrite(plain, 1, MESSAGE_LEN, stdout);
        putchar('\n');
    } else {
        printf("No se encontro la clave.\n");
    }

    printf("Ejecucion: secuencial\n");
    printf("Tiempo: %.6f segundos\n", elapsed);

    EVP_CIPHER_CTX_free(ctx);

    return EXIT_SUCCESS;
}