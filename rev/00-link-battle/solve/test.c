#include <stdio.h>

extern int getflag(int);
int main() {
    printf("%d\n", getflag(6666));
}
