/* Vulnerable target for the enclave-exec executor — a copy of the ret2win
 * challenge, built into a container whose /flag is injected fresh at run time
 * (not baked), so every judging run uses a per-bounty secret flag. */
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
