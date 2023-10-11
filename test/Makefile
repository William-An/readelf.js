# PREFIX := riscv64-unknown-elf-
PREFIX := 
CC := $(PREFIX)gcc

build: helloworld.c
	$(CC) -static -o helloworld.elf $^

clean:
	rm -f *.elf