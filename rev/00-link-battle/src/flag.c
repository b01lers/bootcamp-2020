int g_threadsafe = 0;

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint16_t start_state[6];
static uint16_t lfsr[6];

static char fflag[] = {0xef, 0x64, 0x22, 0xf8, 0xcc, 0xd8, 0xcb, 0x66, 0xc6, 0x3, 0x95, 0xf7, 0xf7, 0xcb, 0xc, 0xd2, 0x24, 0x35, 0xd6, 0xcd, 0xcb, 0x1d, 0x29, 0x46, 0x6a, 0x52, 0x35, 0xcb, 0xe7, 0x66, 0x11, 0x84, 0xa2, 0x5f, 0x53, 0x57, 0xe1, 0xa5, 0xb, 0xd2, 0x4c, 0x43, 0x49, 0x8, 0xda, 0xc4, 0x2, 0x9b, 0x6c, 0x2c, 0xc1, 0xfd, 0x28, 0x6f, 0x2f, 0x79, 0x52, 0xef, 0xbf, 0xee, 0x99, 0x90, 0x41, 0x4a, 0x9f, 0x5f, 0x65, 0x21, 0x64, 0xd8, 0x8a, 0xf5, 0x37, 0x1c, 0x19, 0x45, 0xf1, 0x7, 0x00};

static inline void init_galois(void) {
    memcpy(start_state, (uint16_t[]){0x7b1d, 0x6381, 0xdf77, 0x2122, 0x887a, 0xbbb8}, sizeof(start_state));
    memcpy(lfsr, start_state, sizeof(uint16_t) * 6);
}

/* Uses the feedback of 6 LFSRs to combine into a keystream.
 * Note: this is NOT secure! */
static inline unsigned char galois(void) {
    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < i; j++) {
#ifndef LEFT
            unsigned lsb = lfsr[i] & 1u;  /* Get LSB (i.e., the output bit). */
            lfsr[i] >>= 1;                /* Shift register */
            if (lsb)                   /* If the output bit is 1, */
                lfsr[i] ^= 0xB400u;       /*  apply toggle mask. */
#else
            unsigned msb = (int16_t) lfsr[i] < 0;   /* Get MSB (i.e., the output bit). */
            lfsr[i] <<= 1;                          /* Shift register */
            if (msb)                             /* If the output bit is 1, */
                lfsr[i] ^= 0x002Du;                 /*  apply toggle mask. */
#endif
        }
    }
    uint16_t res = lfsr[0];
    for (int i = 1; i < 6; i++) {
        res ^= lfsr[i];
        res ^= lfsr[i] >> 1;
        res ^= lfsr[i] << 1;
    }
    unsigned char f = ((unsigned char *)&res)[0];
    f ^= ((unsigned char *)&res)[1];
    return res;
}

int getflag(int key) {
    if (key == 6666) {
        char * hint = "If you're reverse engineering me past this point...you're doing the challenge wrong!";
        init_galois();
        for (int i = 0; i < strlen(fflag); i++) {
            unsigned char c = galois();
            printf("%c", fflag[i] ^ c);
        }
        return 1;
    } else {
        return 0;
    }
}
