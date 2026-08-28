/* Vulnerable target for the hunter-VM POC — a copy of examples/ret2win/src/ret2win.c
 * kept here so the Docker build context is self-contained.
 *
 * Classic ret2win: main() reads 256 bytes into a 32-byte buffer, so a 40-byte
 * padding (32 buf + 8 saved rbp) followed by the address of win() redirects
 * execution into win(), which reads and prints /flag. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    FILE *f = fopen("/flag", "r");
    char buf[64];
    if (f && fgets(buf, sizeof buf, f)) {
        puts(buf);
        fflush(stdout);
    }
    exit(0);
}

int main(void) {
    char buf[32] = {0};
    puts("== ret2win: overflow the buffer, reach win() ==");
    fflush(stdout);
    read(0, buf, 256);
    puts("nope");
    fflush(stdout);
    return 0;
}
