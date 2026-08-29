#include <stdio.h>
#include <unistd.h>
/* The authed field sits right after buf in memory (struct order is guaranteed),
 * so reading 128 bytes into a 32-byte buffer overflows into authed. */
int main(void) {
    struct { char buf[32]; long authed; } s = {{0}, 0};
    puts("== admin panel ==");
    puts("password:");
    fflush(stdout);
    read(0, s.buf, 128);
    if (s.authed) {
        FILE *f = fopen("/flag", "r");
        char fb[80];
        if (f && fgets(fb, sizeof fb, f)) fputs(fb, stdout);
    } else {
        puts("access denied");
    }
    fflush(stdout);
    return 0;
}
