#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>

int main(){
    setvbuf(stderr, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char line[] = "testest!\n";
    printf("stdout: %p\n", stdout);
    fwrite(line, 1, strlen(line), stdout);

    return 0;
}