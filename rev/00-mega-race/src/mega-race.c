#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ncurses.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>


// flag{c0ngr4tul4t10nz_y0u_ar3_th3_GUY!}

#define PASSLEN 0x27
#define KEY 0x77
#define WAIT 9
#define DELAY 40000
#define BARRELS 7
#define NORMAL 1
#define RED 2


const unsigned int SPEED = 1;
const unsigned int CSPEED = 4;

typedef struct sprite {
    unsigned int x;
    unsigned int y;
    unsigned int len;
    char ** art;
} sprite;

const static char pass[PASSLEN] = {0x11, 0x1b, 0x16, 0x10, 0xc, 0x14, 0x47, 0x19, 0x10, 0x5, 0x43, 0x3, 0x2, 0x1b, 0x43, 0x3, 0x46, 0x47, 0x19, 0xd, 0x28, 0xe, 0x47, 0x2, 0x28, 0x16, 0x5, 0x44, 0x28, 0x3, 0x1f, 0x44, 0x28, 0x30, 0x22, 0x2e, 0x56, 0xa, 0x0};
static sprite * barrels[BARRELS];
static int framectr = 0;
static char ** barrelptr = NULL;
static int barrellen = 0;
static sprite * cycle;
static int maxx;
static int maxy;
static int dodge = 9999;
enum direction {
    UP = 0,
    DOWN = 1,
    NONE = 2
};
static enum direction dir = NONE;

void * control_loop(void * ptr) {
    while(true) {
    }
    return NULL;
}

void scram(char * passwd) {
    size_t len = strlen(passwd);
    for (size_t i = 0; i < len; i++) {
        passwd[i] = passwd[i] ^ KEY;
    }

}

char * getpasswd(size_t len) {
    char * passwd = (char *) calloc(len + 1, sizeof(char));
    if (!fgets(passwd, len, stdin)) {
        exit(1);
    }
    passwd[len] = '\0';
    return passwd;
}

bool asdfghjkl() {
    printf("ENTER THE CHECKERED FLAG: ");
    char * passwd = getpasswd(PASSLEN);
    scram(passwd);
    if (!strncmp(passwd, pass, PASSLEN)) {
        return true;
    }
    return false;
}

void countdown(void) {
    printf("POTENTIAL EPILEPSY WARNING. YOU HAVE UNTIL THE COUNTDOWN TO HIT CTRL+C OR CLOSE YOUR TERMINAL\n");
    printf("START YOUR ENGINES IN ");
    for (int i = WAIT; i > 0; i--) {
        printf("%d", i);
        fflush(stdout);
        sleep(1);
        printf("\b \b");
    }
}

void getcycle(void) {
    cycle = (sprite *)calloc(1, sizeof(sprite));
    FILE * cyclefile = fopen("./arts/cycle.asc", "r");
    if (!cyclefile) {
        printf("Error!\n");
        exit(1);
    }
    fseek(cyclefile, 0, SEEK_END);
    size_t size = ftell(cyclefile);
    rewind(cyclefile);
    char * cyclebuf = (char *)calloc(size + 1, sizeof(char));
    cycle->len = 0;

    if (!fread(cyclebuf, sizeof(char), size, cyclefile)) {
        return;
    }

    char * last = cyclebuf;
    for (unsigned int i = 0; i < size; i++) {
        if (cyclebuf[i] == '\n') {
            if (cycle->len == 0) {
                cycle->art = (char **) calloc(1, sizeof(char *));
                if (!cycle->art) {
                    printf("Error!\n");
                    exit(1);
                }
            } else {
                cycle->art = realloc(cycle->art, (cycle->len + 1) * sizeof(char *));
                if (!cycle->art) {
                    printf("Error!\n");
                    exit(1);
                }
            }
            cycle->art[cycle->len] = (char *) calloc(&cyclebuf[i] - last + 1, sizeof(char));
            if (cycle->len != 0) {
                memcpy(cycle->art[cycle->len], last + 1, (&cyclebuf[i] - last) - 1);
            } else {
                memcpy(cycle->art[cycle->len], last, (&cyclebuf[i] - last) - 1);
            }
            cycle->len++;
            last = &cyclebuf[i];
        }
    }
    cycle->x = 0;
    cycle->y = (maxy / 2) - (cycle->len / 2);
}

void getbarrel(void) {
    char ** art;
    FILE * barrelfile = fopen("./arts/barrel.asc", "r");
    if (!barrelfile) {
        printf("Error!\n");
        exit(1);
    }
    fseek(barrelfile, 0, SEEK_END);
    size_t size = ftell(barrelfile);
    rewind(barrelfile);
    char * barrelbuf = (char *)calloc(size + 1, sizeof(char));
    barrellen = 0;

    if (!fread(barrelbuf, sizeof(char), size, barrelfile)) {
        return;
    }

    char * last = barrelbuf;
    for (unsigned int i = 0; i < size; i++) {
        if (barrelbuf[i] == '\n') {
            if (barrellen == 0) {
                art = (char **) calloc(1, sizeof(char *));
                if (!art) {
                    printf("Error!\n");
                    exit(1);
                }
            } else {
                art = realloc(art, (barrellen + 1) * sizeof(char *));
                if (!art) {
                    printf("Error!\n");
                    exit(1);
                }
            }
            art[barrellen] = (char *) calloc(&barrelbuf[i] - last + 1, sizeof(char));
            if (barrellen != 0) {
                memcpy(art[barrellen], last + 1, (&barrelbuf[i] - last) - 1);
            } else {
                memcpy(art[barrellen], last, (&barrelbuf[i] - last) - 1);
            }
            barrellen++;
            last = &barrelbuf[i];
        }
    }
    barrelptr = art;
}

void init_curses(void) {
    initscr();
    noecho();
    curs_set(0);
    keypad(stdscr, true);
    start_color();
    init_pair(NORMAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(RED, COLOR_RED, COLOR_BLACK);
}

void initbarrels(void) {
    srand(time(NULL));
    int interval = (maxx - 40) / BARRELS;
    for (int i = 0; i < BARRELS; i++) {
        barrels[i] = (sprite *) calloc(1, sizeof(sprite));
        barrels[i]->len = barrellen;
        barrels[i]->art = barrelptr;
        barrels[i]->x = (i * interval) + 40;
        barrels[i]->y = (rand() % (maxy - barrels[i]->len));
    }
}

bool init_race(void) {
    if (!asdfghjkl()) {
        printf("Sorry kid, you don't have what it takes...but you better show us anyway!\nWELCOME. TO. MEGA RACE!\n");
        countdown();
        init_curses();
        getmaxyx(stdscr, maxy, maxx);
        timeout(1);
        getcycle();
        getbarrel();
        initbarrels();
        return true;
    } else {
        printf("Wow, you really hacked the OSS password? Nice work!\n");
        return false;
    }
}

void draw_cycle(void) {
    for (int i = 0; i < cycle->len; i++) {
        mvprintw(cycle->y + i, 0, cycle->art[i]);
    }
}

void draw_barrels(void) {
    for (int i = 0; i < BARRELS; i++) {
        for (int j = 0; j < barrels[i]->len; j++) {
            mvprintw(barrels[i]->y + j, barrels[i]->x, barrels[i]->art[j]);
        }
    }
}

void draw_stats(void) {
    mvprintw(maxy - 1, 0, "Use the up/down/right arrows to drive! Dodge %d more barrels to win!", dodge);
}

void movement(void) {
    for (int i = 0; i < BARRELS; i++) {
        barrels[i]->x = (barrels[i]->x - SPEED) % maxx;
        if (barrels[i]->x == maxx - strlen(barrels[i]->art[3])) {
            barrels[i]->y = (rand() % (maxy - barrels[i]->len));
            barrels[i]->x -= (rand() % (maxx / 10));
            dodge--;
        }
    }
    int ch = wgetch(stdscr);
    if (ch == KEY_UP) {
        dir = UP;
    } else if (ch == KEY_DOWN) {
        dir = DOWN;
    } else if (ch == KEY_RIGHT) {
        dir = NONE;
    } else if (ch == ERR) {
        dir = NONE;
    }
    if (dir == UP) {
        cycle->y = (cycle->y - CSPEED) > 0 ? (cycle->y - CSPEED) : 0;
    } else if (dir == DOWN) {
        cycle->y = (cycle->y + CSPEED) < (maxy - cycle->len) ? (cycle->y + CSPEED) : (maxy - cycle->len); 
    }

    return;
}

void check(void) {
    for (int i = 0; i < BARRELS; i++) {
        int xbuf = strlen(barrels[i]->art[3]);
        int ybuf = barrels[i]->len;
        int cylen = strlen(cycle->art[3]);
        /* lol dat nest */
        for (int y = barrels[i]->y; y < barrels[i]->y + ybuf; y++) {
            for (int x = barrels[i]->x; x < barrels[i]->x + xbuf; x++) {
                if ((x < cycle->x + cylen - 1 && x > cycle->x + 1) && (y < cycle->y - 2 + ybuf && y > cycle->y + 1)) {
                    for (int i = 0; i < maxy; i++) {
                        for (int j = 0, k=0; j < maxx / strlen("FAIL"); j++, k+=strlen("FAIL")) {
                            attron(COLOR_PAIR(RED));
                            mvprintw(i, k, "FAIL");
                            attron(COLOR_PAIR(NORMAL));
                        }
                    }
                    dodge++;
                }
            }
        }
    }
    if (dodge == 0) {
        endwin();
        printf("Congratulations, you won! The checkered flag is: [REDACTED]\n");
        exit(0);
    }
}

void frame(void) {
    draw_cycle();
    draw_barrels();
    draw_stats();
    movement();
    check();
    framectr++;
}

void begin_race(void) {
    pthread_t eventhread;
    int err;
    if ((err = pthread_create(&eventhread, NULL, &control_loop, NULL))) {
        printf("Error creating event thread\n");
        endwin();
        exit(0);
    }
    while (true) {
        clear();
        frame();
        refresh();
        usleep(DELAY);
    }
}

int main() {
    if (!init_race()) {
        return 1;
    }
    begin_race();
    endwin();
}

