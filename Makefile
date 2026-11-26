CC     ?= gcc
CFLAGS ?= -O2 -march=native -Wall

.PHONY: all test bench proverif clean

all: cpus

cpus: cpus.c
	$(CC) $(CFLAGS) cpus.c -o cpus -lcrypto -lm

test: cpus
	./cpus

bench: cpus
	./cpus bench 30

proverif:
	cd proverif && PV=$${PV:-proverif} sh run_all.sh

clean:
	rm -f cpus
