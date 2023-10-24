# PREFIX := riscv64-unknown-elf-
PREFIX := 
CC := $(PREFIX)gcc
EXE := helloworld.elf

build: helloworld.c
	$(CC) -o $(EXE) $^

static: helloworld.c
	$(CC) -static -o $(EXE) $^

clean:
	rm -f *.elf