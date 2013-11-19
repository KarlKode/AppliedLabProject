SHELL = /bin/sh
CFLAGS = -Wall -fno-stack-protector -mpreferred-stack-boundary=2
CC = gcc
all = vulnapp envadd

default: $(all)

vulnapp: vulnapp.c
	$(CC) $(CFLAGS) $< -o $@
	sudo chown root  $@
	sudo chmod u+s $@

envadd: envadd.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(all)
