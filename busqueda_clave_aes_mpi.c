/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Laboratorio: 03  (version paralela con Open MPI)
 *
 * Compilacion:
 *   mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi.c \
 *       -o busqueda_clave_aes_mpi -lcrypto
 * Ejecucion:
 *   mpirun -np 4 ./busqueda_clave_aes_mpi [-b bits] [-k clave] [-m mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define KEY_LEN 16
#define BLOCK_LEN 16
#define MAX_MESSAGE_LEN 1024
#define DEFAULT_BITS 24
#define CHECK_INTERVAL 4096   /* cada cuantas claves se consulta a los demas */

static const char default_message[] =
    "Puedes lograrlo! La computacion paralela acelera la busqueda.";
static const char default_crib[] = "Puedes lograrlo";

static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}

/* La clave de 128 bits: base en los bytes altos, candidata en los b bits bajos. */
static void make_key(
    const unsigned char base[KEY_LEN],
    uint64_t candidate, int bits, unsigned char key[KEY_LEN])
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

static int encrypt_message(
    const unsigned char key[KEY_LEN], const unsigned char iv[BLOCK_LEN],
    const unsigned char *input, int input_len, unsigned char *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int written = 0, final_written = 0;

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
 * Acepta la candidata solo si el relleno PKCS#7 es valido y el texto
 * contiene el fragmento conocido. Devuelve la longitud del texto plano
 * o -1 si la clave no sirve.
 */
static int try_candidate(
    EVP_CIPHER_CTX *ctx, const unsigned char key[KEY_LEN],
    const unsigned char iv[BLOCK_LEN],
    const unsigned char *cipher, int cipher_len,
    const unsigned char *crib, int crib_len, unsigned char *plain)
{
    int written = 0, final_written = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &written, cipher, cipher_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain + written, &final_written) != 1) {
        return -1;
    }

    int plain_len = written + final_written;

    if (!contains(plain, plain_len, crib, crib_len)) {
        return -1;
    }

    return plain_len;
}

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    int bits = DEFAULT_BITS;
    uint64_t secret = UINT64_C(12345);
    char text[MAX_MESSAGE_LEN + 1];
    strcpy(text, default_message);
    int opt;

    while ((opt = getopt(argc, argv, "b:k:m:h")) != -1) {
        switch (opt) {
        case 'b': bits = atoi(optarg); break;
        case 'k': secret = strtoull(optarg, NULL, 10); break;
        case 'm':
            strncpy(text, optarg, MAX_MESSAGE_LEN);
            text[MAX_MESSAGE_LEN] = '\0';
            break;
        case 'h':
        default:
            if (rank == 0) {
                fprintf(stderr,
                    "Uso: mpirun -np P %s [-b bits] [-k clave] [-m mensaje]\n",
                    argv[0]);
            }
            MPI_Finalize();
            return EXIT_FAILURE;
        }
    }

    if (bits < 1 || bits > 32) {
        if (rank == 0) {
            fprintf(stderr, "Los bits de busqueda deben estar entre 1 y 32.\n");
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    int text_len = (int)strlen(text);
    uint64_t total_keys = UINT64_C(1) << bits;

    unsigned char base[KEY_LEN];
    unsigned char iv[BLOCK_LEN];
    unsigned char cipher[MAX_MESSAGE_LEN + BLOCK_LEN];
    int cipher_len = 0;

    /*
     * El proceso 0 prepara el criptograma y difunde todo lo necesario.
     * Asi todos los procesos descifran exactamente el mismo problema.
     */
    if (rank == 0) {
        if (secret >= total_keys) {
            fprintf(stderr, "La clave secreta no cabe en %d bits.\n", bits);
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
        }
        if (RAND_bytes(base, KEY_LEN) != 1 || RAND_bytes(iv, BLOCK_LEN) != 1) {
            fail("No se pudo generar material aleatorio.");
        }
        unsigned char true_key[KEY_LEN];
        make_key(base, secret, bits, true_key);
        cipher_len = encrypt_message(
            true_key, iv, (const unsigned char *)text, text_len, cipher);
    }

    MPI_Bcast(base, KEY_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(iv, BLOCK_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cipher_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(cipher, cipher_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    const unsigned char *crib = (const unsigned char *)default_crib;
    int crib_len = (int)strlen(default_crib);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    unsigned char plain[MAX_MESSAGE_LEN + BLOCK_LEN];
    unsigned char local_plain[MAX_MESSAGE_LEN + BLOCK_LEN];
    long local_found = -1;   /* clave hallada por este proceso, o -1 */
    int local_len = 0;

    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    /*
     * Reparto ciclico del rango: el proceso r prueba r, r+P, r+2P, ...
     * La senal de terminacion se propaga con mensajes punto a punto (no
     * colectivos): quien encuentra la clave avisa a todos con MPI_Isend y
     * los demas sondean con MPI_Iprobe. Se evitan colectivos dentro del
     * bucle, donde cada proceso recorre un numero distinto de candidatas
     * y una colectiva mal emparejada provocaria interbloqueo. Si nadie
     * encuentra la clave, cada proceso agota su rango y el bucle termina
     * por si solo.
     */
    const int TAG_STOP = 7;
    int someone_done = 0;
    unsigned long counter = 0;

    MPI_Request *stop_reqs = malloc(sizeof(MPI_Request) * (size_t)size);
    int sent_stop = 0;
    char stop_msg = 1;

    for (uint64_t candidate = (uint64_t)rank;
         candidate < total_keys;
         candidate += (uint64_t)size) {

        unsigned char key[KEY_LEN];
        make_key(base, candidate, bits, key);

        int len = try_candidate(
            ctx, key, iv, cipher, cipher_len, crib, crib_len, plain);

        if (len >= 0) {
            local_found = (long)candidate;
            local_len = len;
            memcpy(local_plain, plain, (size_t)len);

            /* Avisa a todos los demas procesos que pueden detenerse. */
            for (int p = 0; p < size; p++) {
                if (p == rank) {
                    stop_reqs[p] = MPI_REQUEST_NULL;
                } else {
                    MPI_Isend(&stop_msg, 1, MPI_CHAR, p, TAG_STOP,
                              MPI_COMM_WORLD, &stop_reqs[p]);
                }
            }
            sent_stop = 1;
            break;
        }

        /* Sondea periodicamente si alguien ya aviso que termino. */
        if (++counter % CHECK_INTERVAL == 0) {
            int flag = 0;
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, MPI_COMM_WORLD, &flag,
                       MPI_STATUS_IGNORE);
            if (flag) {
                someone_done = 1;
                break;
            }
        }
    }

    (void)someone_done;

    /* Completa los avisos enviados, si este proceso fue el que encontro. */
    if (sent_stop) {
        for (int p = 0; p < size; p++) {
            if (p != rank) {
                MPI_Wait(&stop_reqs[p], MPI_STATUS_IGNORE);
            }
        }
    }
    free(stop_reqs);

    /*
     * Barrera: tras completar los MPI_Wait de los avisos, garantiza que
     * todos los procesos llegaron aqui y que los avisos ya estan en las
     * colas de recepcion antes de drenarlos.
     */
    MPI_Barrier(MPI_COMM_WORLD);

    /*
     * Drena cualquier aviso de parada pendiente para que no queden
     * mensajes sin recibir antes de MPI_Finalize.
     */
    int flag = 1;
    while (flag) {
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, MPI_COMM_WORLD, &flag,
                   MPI_STATUS_IGNORE);
        if (flag) {
            char drain;
            MPI_Recv(&drain, 1, MPI_CHAR, MPI_ANY_SOURCE, TAG_STOP,
                     MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }
    }

    /*
     * Determina la menor clave encontrada y quien la tiene, con MINLOC.
     * Si un proceso no encontro nada, aporta un valor muy grande.
     */
    struct { long key; int rank; } mine, best;
    mine.key = (local_found >= 0) ? local_found : (long)total_keys;
    mine.rank = rank;
    MPI_Allreduce(&mine, &best, 1, MPI_LONG_INT, MPI_MINLOC,
                  MPI_COMM_WORLD);

    double elapsed = MPI_Wtime() - start;
    double max_elapsed = 0.0;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0,
               MPI_COMM_WORLD);

    /* El dueño de la mejor clave envia el texto plano al proceso 0. */
    int winner = best.rank;
    long winner_key = best.key;

    if (winner_key < (long)total_keys) {
        if (rank == winner && rank != 0) {
            MPI_Send(&local_len, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
            MPI_Send(local_plain, local_len, MPI_UNSIGNED_CHAR, 0, 2,
                     MPI_COMM_WORLD);
        }
        if (rank == 0) {
            if (winner == 0) {
                memcpy(plain, local_plain, (size_t)local_len);
            } else {
                MPI_Recv(&local_len, 1, MPI_INT, winner, 1, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE);
                MPI_Recv(plain, local_len, MPI_UNSIGNED_CHAR, winner, 2,
                         MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
        }
    }

    if (rank == 0) {
        if (winner_key < (long)total_keys) {
            printf("Clave encontrada: %ld\n", winner_key);
            printf("Mensaje: ");
            fwrite(plain, 1, (size_t)local_len, stdout);
            putchar('\n');
        } else {
            printf("No se encontro la clave.\n");
        }
        printf("Ejecucion: paralela MPI\n");
        printf("Procesos: %d\n", size);
        printf("Bits de busqueda: %d  (espacio explorado: %" PRIu64 ")\n",
               bits, total_keys);
        printf("Tiempo: %.6f segundos\n", max_elapsed);
    }

    EVP_CIPHER_CTX_free(ctx);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
