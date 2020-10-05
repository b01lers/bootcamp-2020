#include <stdio.h>
#include <ncurses.h>
#include <unistd.h>
#include <string.h>


#define THUMB0 "            ,voZ5#V4J#VV$#z)-"                                                                  
#define THUMB1 "          .T91+           ?TI#Y:"                                                               
#define THUMB2 "          Ys_   '(vv/|v|<!      fo>."                                                            
#define THUMB3 "          n_ sFfL|i/|v[Yt1x7(:~'!L]:"                                                           
#define THUMB4 "          I  F`               )i_ /O:"                                                          
#define THUMB5 "          & D7                 5a _wF"                                                          
#define THUMB6 "          B NY                  M  }D"                                                          
#define THUMB7 "          R  9                 Zh   gf"                                                         
#define THUMB8 "         /B  Hi              'vN|   64"                                                         
#define THUMB9 "         y8  Y&<             cD1    sd'"                                                        
#define THUMB10 "         r#   [Oi          ~FDL    'vD!"                                                        
#define THUMB11 "         uY`    4#        Jh1:      ;Q"                                                        
#define THUMB12 "         8/      +Y]?*vtJ]'/:       _M"                                                        
#define THUMB13 "        iR^                          M"                                                        
#define THUMB14 "        vk                           I"                                                        
#define THUMB15 "        |       -72340lskdfj-        [w"                                                        
#define THUMB16 "        Z,                           ^4F"                                                       
#define THUMB17 "        M^        -.8*sd&*)-          <d"
#define THUMB18 "        N,                           ._kI"
#define THUMB19 "      7=HL                           iEOP"
#define THUMB20 "    $6bp&9                         ibO9$k$"
#define THUMB21 " 5$5ZXXXEN.                         GXk55X5$"
#define THUMB22 "XXXZXXX$XS@9                  ^/w&GXZ5ZkXkX$"
#define THUMB23 "k$ZXkZ55kZ5KDy              _vmNAk5Zk$kX$$XZ"
#define THUMB24 "ZZ555$5$kX$ZSMMF<         ~YqOw$$$5XkX$X$5ZX"
#define THUMB25 "$Z$$$$$XZ5$$Z5ZbOAL:     FKb9$5XZZXX5k$Z$5kP"
#define THUMB26 "$5k5kZkX5k5$k5kkZ5m83Yle6PZ5$55ZZZZ$5$Z5ZZk5"
#define THUMB27 "$X$5$XkZZkX5kZ5$$kX5kX$XkZkZkZXXkZZk55$Zk5$X"
#define THUMB28 "$k5XZZkkZX5XkkZ$kZ5XZk$$k$Z5XXk$X5kZ5XX$$Zkk"
#define THUMB29 "AZXkkX$ZXZkZXk55$kX$$kP8k$AO6$k$ZXZk$5kXZkZE"
#define THUMB30 "@X$k$5kX$E&qhXGmqEOKMb8hkP.p.Op555Xk5$5kXk$w"

#define SIDEBUFFER 44
#define TOPBUFFER 30

#define NORMAL 1
#define RED 2

static int delay = 50000;
static int y = 0;
static int x = 0;
static int maxx = 0;
static int maxy = 0;
static void (*curmovfunc)(void);


void thumblings_assemble(void) {
    // flag{s3nd_0ur_b3st_thumb5}
    int asdf[0x1a];
    asdf[0x00] = 'f';
    asdf[0x15] = 'u';
    asdf[0x04] = '{';
    asdf[0x07] = 'n';
    asdf[0x09] = '_';
    asdf[0x16] = 'm';
    asdf[0x0a] = '0';
    asdf[0x0f] = '3';
    asdf[0x14] = 'h';
    asdf[0x16] = 'm';
    asdf[0x17] = 'b';
    asdf[0x0c] = 'r';
    asdf[0x0d] = '_';
    asdf[0x0e] = 'b';
    asdf[0x11] = 't';
    asdf[0x08] = 'd';
    asdf[0x12] = '_';
    asdf[0x0b] = 'u';
    asdf[0x13] = 't';
    asdf[0x06] = '3';
    asdf[0x01] = 'l';
    asdf[0x02] = 'a';
    asdf[0x03] = 'g';
    asdf[0x05] = 's';
    asdf[0x14] = 'h';
    asdf[0x17] = 'b';
    asdf[0x10] = 's';
    asdf[0x18] = '5';
    asdf[0x19] = '}';
    for (int i = 0; i < 0x1a; i++) {
        asdf[i] = 0;
    }

}

void downright(void) {
    x++;
    y++;
}

void downleft(void) {
    x--;
    y++;
}

void upright(void) {
    x++;
    y--;
}

void upleft(void) {
    x--;
    y--;
}

int clampdelay(int delay) {
    delay -= 20;
    return (delay < 0) ? 50000 : delay;
}

void checkcurmovfunc(void) {
    getmaxyx(stdscr, maxy, maxx);
    maxy -= TOPBUFFER;
    maxx -= SIDEBUFFER;
    if (curmovfunc == downright) {
        if (x >= maxx && y >= maxy) {
            curmovfunc = upleft;
        }
        if (x >= maxx) {
            curmovfunc = downleft;
        } else if (y >= maxy) {
            curmovfunc = upright;
        }
    } else if (curmovfunc == downleft) {
        if (x >= maxx && y >= maxy) {
            curmovfunc = upright;
        }
        if (x <= 0) {
            curmovfunc = downright;
        } else if (y >= maxy) {
            curmovfunc = upleft;
        }
    } else if (curmovfunc == upright) {
        if (x >= maxx && y >= maxy) {
            curmovfunc = downleft;
        }
        if (x >= maxx) {
            curmovfunc = upleft;
        } else if (y <= 0) {
            curmovfunc = downright;
        }
    } else if (curmovfunc == upleft) {
        if (x >= maxx && y >= maxy) {
            curmovfunc = downright;
        }
        if (x <= 0) {
            curmovfunc = upright;
        } else if (y <= 0) {
            curmovfunc = downleft;
        }
    }
}

void thumblings_engage(void) {
    initscr();
    noecho();
    curs_set(0);
    curmovfunc = downright;
    start_color();
    init_pair(NORMAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(RED, COLOR_RED, COLOR_BLACK);
}

void print_thumb() {
    attron(COLOR_PAIR(NORMAL));
    mvprintw(y, x, THUMB0);
    mvprintw(y + 1, x, THUMB1);
    mvprintw(y + 2, x, THUMB2);
    mvprintw(y + 3, x, THUMB3);
    mvprintw(y + 4, x, THUMB4);
    mvprintw(y + 5, x, THUMB5);
    mvprintw(y + 6, x, THUMB6);
    mvprintw(y + 7, x, THUMB7);
    mvprintw(y + 8, x, THUMB8);
    mvprintw(y + 9, x, THUMB9);
    mvprintw(y + 10, x, THUMB10);
    mvprintw(y + 11, x, THUMB11);
    mvprintw(y + 12, x, THUMB12);
    mvprintw(y + 13, x, THUMB13);
    mvprintw(y + 14, x, THUMB14);
    mvprintw(y + 15, x, THUMB15);
    mvprintw(y + 16, x, THUMB16);
    mvprintw(y + 17, x, THUMB17);
    attron(COLOR_PAIR(RED));
    mvprintw(y + 18, x, THUMB18);
    mvprintw(y + 19, x, THUMB19);
    mvprintw(y + 20, x, THUMB20);
    mvprintw(y + 21, x, THUMB21);
    mvprintw(y + 22, x, THUMB22);
    mvprintw(y + 23, x, THUMB23);
    mvprintw(y + 24, x, THUMB24);
    mvprintw(y + 25, x, THUMB25);
    mvprintw(y + 26, x, THUMB26);
    mvprintw(y + 27, x, THUMB27);
    mvprintw(y + 28, x, THUMB28);
    mvprintw(y + 29, x, THUMB29);
    mvprintw(y + 30, x, THUMB30);
    mvprintw(0, 0, "d: %d x: %d y: %d mx: %d my: %d", delay, x, y, maxx, maxy);
    curmovfunc();
    checkcurmovfunc();
}

void thumblings_attack(void) {
    while (1) {
        clear();
        print_thumb();
        refresh();
        usleep(delay);
        delay = clampdelay(delay);
    }
}

void thumblings_retreat(void) {
    endwin();
}

int main(int argc, char ** argv) {
    thumblings_assemble();
    thumblings_engage();
    thumblings_attack();
    thumblings_retreat();
}
