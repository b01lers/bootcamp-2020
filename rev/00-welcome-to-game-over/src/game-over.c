#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PROMPT   "\nsharkboy@gameover > ./getemail.sh\n"
#define INCOMING "**** INCOMING MESSAGE FROM CARMEN ****"
#define MESSAGE  "I was fired.\nI know.\nI hacked into the O.S.S. data files and saw the news.\nIt was probably my fault, I suppose.\nI am sorry."
#define BACKSPACE "\b \b"

void flashprint(char * to_print, int sep_ms, int times) {
    size_t len = strlen(to_print);
    for (int i = 0; i < times; i++) {
        printf("%s", to_print);
        fflush(stdout);
        usleep(sep_ms * 1000);
        for (int i = 0; i < len; i++) {
            printf("%s", BACKSPACE);
        }
        fflush(stdout);
        usleep(sep_ms * 1000);
    }
}

void funprint(char * to_print, int sep_ms) {
    for (int i = 0; i < strlen(to_print); i++) {
        printf("%c", to_print[i]);
        fflush(stdout);
        usleep(sep_ms * 1000);
    }
}

int _my_little_thumbling(char * flag) {
    return flag[0];
}

int main(void) {
    char * flag_part_a = "flag{welc0me_to_th3_game<FIND_THE_REST_OF_THE_FLAG_IN_FUNCTION_NAMES>}";
    printf("%s", PROMPT);
    fflush(stdout);
    flashprint(INCOMING, 700, 5);
    funprint(MESSAGE, 300);
    return _my_little_thumbling(flag_part_a);
}
