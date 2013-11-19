#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LENGTH 64
char* egg = "EASTEREGG";
char input[BUFFER_LENGTH];

int cpybuf(char *mbuf) {
  int ret = 0;
  char buff[16];

  strcpy(buff,mbuf);
  ret = printf("You provided:[%s]\n",buff);

  return ret;
}


int main(int argc, char **argv) {
  if (argc != 2) {
    puts("Usage: vulnapp <user input>");
    exit(1);
  }

  setuid(0);

  printf("Type some text:\n");
  
  char *p = fgets(input,BUFFER_LENGTH,stdin);
  if (p == NULL) {
     printf("An error reading from stdin\n");
     exit(1);
  } else {
    size_t last = strlen(input) - 1;
    if (input[last] == '\n') input[last] = '\0';
    printf("\nYou typed: [%s]\n",input);
  }

  cpybuf(argv[1]);
  return(0);
}
