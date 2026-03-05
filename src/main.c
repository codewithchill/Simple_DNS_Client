#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "dns.h"
#include "color.h"

void exit_handle(void) {
    printf("%s\nDNS Resolver exiting......\n%s", FG_CYAN, RESET);
}

int main(int argc, char **argv) {

    setbuf(stdout, NULL);

    if ( atexit(exit_handle) != 0 ) {
        fprintf(stderr, "Failed to register exit function\n");
        return 1;
    }

    printf("%s\nDNS Resolver starting.....\n%s", FG_CYAN, RESET);
    srand(time(NULL));

    parse_arguments(argc, argv);
    dns_query(argv[1]);

    return 0;
}

