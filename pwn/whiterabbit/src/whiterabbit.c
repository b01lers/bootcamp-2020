#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>


int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("Follow the white rabbit.\n");
    printf("Path to follow: ");

    char buffer[64];

    scanf("%s", buffer);
    if(strstr(buffer, "flag") != NULL) {
        printf("No printing the flag.\n");
        exit(0);
    }
    
    char line[256];
    sprintf(line, "[ -f '%1$s' ] && cat '%1$s' || echo File does not exist", buffer);
    system(line);
}
