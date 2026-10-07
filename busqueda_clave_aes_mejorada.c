/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Laboratorio: 03  (version secuencial corregida y mejorada)
 *
 *
 * Compilacion:
 *   gcc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mejorada.c \
 *       -o busqueda_clave_aes_mejorada -lcrypto
 * Uso:
 *   ./busqueda_clave_aes_mejorada [-b bits] [-k clave] [-m mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define KEY_LEN 16
#define BLOCK_LEN 16
#define MAX_MESSAGE_LEN 1024
#define DEFAULT_BITS 24

static const char default_message[] =
    "Puedes lograrlo! La computacion paralela acelera la busqueda.";
static const char default_crib[] = "Puedes lograrlo";

/* Muestra el error y termina el programa. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * M1: la clave completa tiene 128 bits. Los bytes altos provienen de la
 * base; en los b bits bajos se inserta la candidata.
 */
static void make_key(
    const unsigned char base[KEY_LEN],
    uint64_t candidate,
    int bits,
    unsigned char key[KEY_LEN])
{
    memcpy(key, base, KEY_LEN);

    for (int i = 0; i < 8 && 8 * i < bits; i++) {
        unsigned char mask = 0xFF;

        if (bits - 8 * i < 8) {
            mask = (unsigned char)((1u << (bits - 8 * i)) - 1u);
        }

        unsigned char value =
            (unsigned char)((candidate >> (8 * i)) & UINT64_C(0xFF));

        key[KEY_LEN - 1 - i] =
            (unsigned char)((key[KEY_LEN - 1 - i] & ~mask) | (value & mask));
    }
}

/* Equivalente portable de memmem: busca needle dentro de haystack. */
static int contains(
    const unsigned char *haystack, int haystack_len,
    const unsigned char *needle, int needle_len)
{
    if (needle_len <= 0) {
        return 1;
    }

    for (int i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(haystack + i, needle, (size_t)needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

/* M2: cifra el mensaje con AES-128-CBC y relleno PKCS#7. */
static int encrypt_message(
    const unsigned char key[KEY_LEN],
    const unsigned char iv[BLOCK_LEN],
    const unsigned char *input, int input_len,
    unsigned char *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int written = 0;
    int final_written = 0;

    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, output, &written, input, input_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, output + written, &final_written) != 1) {
        fail("Error al cifrar el mensaje.");
    }

    EVP_CIPHER_CTX_free(ctx);
    return written + final_written;
}

/*
 * Intenta descifrar el criptograma con la clave candidata.
 * M3/M5: una clave es aceptada solo si el relleno PKCS#7 es valido
 * (EVP_DecryptFinal_ex lo verifica) y el texto resultante contiene el
 * fragmento conocido. No se compara contra el mensaje original completo.
 * Devuelve la longitud del texto plano, o -1 si la clave no sirve.
 */
static int try_candidate(
    EVP_CIPHER_CTX *ctx,
    const unsigned char key[KEY_LEN],
    const unsigned char iv[BLOCK_LEN],
    const unsigned char *cipher, int cipher_len,
    const unsigned char *crib, int crib_len,
    unsigned char *plain)
{
    int written = 0;
    int final_written = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plain, &written, cipher, cipher_len) != 1) {
        return -1;
    }

    /* Clave incorrecta: casi siempre falla aqui por relleno invalido. */
    if (EVP_DecryptFinal_ex(ctx, plain + written, &final_written) != 1) {
        return -1;
    }

    int plain_len = written + final_written;

    if (!contains(plain, plain_len, crib, crib_len)) {
        return -1;
    }

    return plain_len;
}

/* Tiempo de un reloj monotono, en segundos. */
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

int main(int argc, char **argv)
{
    int bits = DEFAULT_BITS;
    uint64_t secret = UINT64_C(12345);
    const char *text = default_message;
    int opt;

    /* M6: configuracion por linea de comandos. */
    while ((opt = getopt(argc, argv, "b:k:m:h")) != -1) {
        switch (opt) {
        case 'b': bits = atoi(optarg); break;
        case 'k': secret = strtoull(optarg, NULL, 10); break;
        case 'm': text = optarg; break;
        case 'h':
        default:
            fprintf(stderr,
                "Uso: %s [-b bits] [-k clave] [-m mensaje]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (bits < 1 || bits > 32) {
        fprintf(stderr, "Los bits de busqueda deben estar entre 1 y 32.\n");
        return EXIT_FAILURE;
    }

    int text_len = (int)strlen(text);
    if (text_len == 0 || text_len > MAX_MESSAGE_LEN) {
        fprintf(stderr, "Longitud de mensaje invalida.\n");
        return EXIT_FAILURE;
    }

    uint64_t total_keys = UINT64_C(1) << bits;
    if (secret >= total_keys) {
        fprintf(stderr,
            "La clave secreta no cabe en %d bits.\n", bits);
        return EXIT_FAILURE;
    }

    /* M1: base de 128 bits aleatoria e IV aleatorio para el cifrado. */
    unsigned char base[KEY_LEN];
    unsigned char iv[BLOCK_LEN];
    if (RAND_bytes(base, KEY_LEN) != 1 || RAND_bytes(iv, BLOCK_LEN) != 1) {
        fail("No se pudo generar material aleatorio.");
    }

    /* Prepara el criptograma con la clave secreta "verdadera". */
    unsigned char true_key[KEY_LEN];
    make_key(base, secret, bits, true_key);

    unsigned char cipher[MAX_MESSAGE_LEN + BLOCK_LEN];
    int cipher_len = encrypt_message(
        true_key, iv, (const unsigned char *)text, text_len, cipher);

    const unsigned char *crib = (const unsigned char *)default_crib;
    int crib_len = (int)strlen(default_crib);

    /* M4: el contexto EVP se crea una sola vez y se reutiliza en el
     * bucle; por candidata solo se reinicializa la clave. */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    unsigned char plain[MAX_MESSAGE_LEN + BLOCK_LEN];
    uint64_t found = UINT64_MAX;
    int found_len = 0;

    double start = get_time();

    for (uint64_t candidate = 0; candidate < total_keys; candidate++) {
        unsigned char key[KEY_LEN];
        make_key(base, candidate, bits, key);

        int len = try_candidate(
            ctx, key, iv, cipher, cipher_len, crib, crib_len, plain);

        if (len >= 0) {
            found = candidate;
            found_len = len;
            break;
        }
    }

    double elapsed = get_time() - start;

    if (found != UINT64_MAX) {
        printf("Clave encontrada: %" PRIu64 "\n", found);
        printf("Mensaje: ");
        fwrite(plain, 1, (size_t)found_len, stdout);
        putchar('\n');
    } else {
        printf("No se encontro la clave.\n");
    }

    printf("Ejecucion: secuencial (mejorada)\n");
    printf("Bits de busqueda: %d  (espacio explorado: %" PRIu64 ")\n",
           bits, total_keys);
    printf("Claves probadas: %" PRIu64 "\n",
           (found == UINT64_MAX) ? total_keys : found + 1);
    printf("Tiempo: %.6f segundos\n", elapsed);

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;
}
