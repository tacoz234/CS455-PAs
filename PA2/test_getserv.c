#include <netdb.h>
#include <stdio.h>
int main() {
    struct servent *se = getservbyport(htons(80), NULL);
    if(se) printf("%s\n", se->s_name);
    return 0;
}
