#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

void printElf(uint8_t ei_class, void *elfHeader, 
              void *programHeaderTable, void *sectionHeaderTable, 
              uint16_t ph_num, uint16_t sh_num);
void printElfHeader(uint8_t ei_class, void *elfHeader);
void printElfProgramHeader(uint8_t ei_class, void *programHeaderTable, uint16_t num);
void printElfSectionHeader(uint8_t ei_class, void *sectionHeaderTable, uint16_t num);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Need exactly 1 elf file path, receiving: %d\n", argc - 1);
        return 0;
    }

    // Open elf file
    char *elf_path = argv[argc - 1];
    FILE *elf_fp = fopen(elf_path, "rb");
    if (elf_fp == NULL) {
        printf("Unable to open %s as binary file\n", elf_path);
        return errno;
    }
    
    // Check magic to make sure we are opening an elf file
    unsigned char e_ident_peek[EI_NIDENT];
    size_t count = fread(e_ident_peek, sizeof(char), EI_NIDENT, elf_fp);
    if (count != EI_NIDENT) {
        printf("Unable to read E_IDENT\n");
        return EBADF;
    }

    if ((e_ident_peek[EI_MAG0] != ELFMAG0) || 
        (e_ident_peek[EI_MAG1] != ELFMAG1) ||
        (e_ident_peek[EI_MAG2] != ELFMAG2) ||
        (e_ident_peek[EI_MAG3] != ELFMAG3)) {
        printf("ELF Magic not matched\n");
        return EBADF;
    }

    // Read the file
    int err = fseek(elf_fp, 0, SEEK_SET);
    if (err) {
        return err;
    }
    void *elfHeader;
    void *programHeaderTable;
    void *sectionHeaderTable;
    uint16_t numProgramHeader;
    uint16_t numSectionHeader;
    uint16_t programTableEntrySize;
    uint16_t sectionTableEntrySize;
    Elf64_Off programHeaderTableOffset;
    Elf64_Off sectionHeaderTableOffset;
    if (e_ident_peek[EI_CLASS] == ELFCLASS32) {
        // Read header
        elfHeader = malloc(sizeof(Elf32_Ehdr));
        fread(elfHeader, sizeof(uint8_t), sizeof(Elf32_Ehdr), elf_fp);
        numProgramHeader = ((Elf32_Ehdr *)elfHeader)->e_phnum;
        numSectionHeader = ((Elf32_Ehdr *)elfHeader)->e_shnum;
        programHeaderTable = malloc(sizeof(Elf32_Phdr) * numProgramHeader);
        sectionHeaderTable = malloc(sizeof(Elf32_Shdr) * numSectionHeader);
        programTableEntrySize = sizeof(Elf32_Phdr);
        sectionTableEntrySize = sizeof(Elf32_Shdr);
        programHeaderTableOffset = ((Elf32_Ehdr *)elfHeader)->e_phoff;
        sectionHeaderTableOffset = ((Elf32_Ehdr *)elfHeader)->e_shoff;
    } else if (e_ident_peek[EI_CLASS] == ELFCLASS64) {
        // Read header
        elfHeader = malloc(sizeof(Elf64_Ehdr));
        fread(elfHeader, sizeof(uint8_t), sizeof(Elf64_Ehdr), elf_fp);
        numProgramHeader = ((Elf64_Ehdr *)elfHeader)->e_phnum;
        numSectionHeader = ((Elf64_Ehdr *)elfHeader)->e_shnum;
        programHeaderTable = malloc(sizeof(Elf64_Phdr) * numProgramHeader);
        sectionHeaderTable = malloc(sizeof(Elf64_Shdr) * numSectionHeader);
        programTableEntrySize = sizeof(Elf64_Phdr);
        sectionTableEntrySize = sizeof(Elf64_Shdr);
        programHeaderTableOffset = ((Elf64_Ehdr *)elfHeader)->e_phoff;
        sectionHeaderTableOffset = ((Elf64_Ehdr *)elfHeader)->e_shoff;
    } else {
        printf("Unable to identify ELF class\n");
        return EBADF;
    }

    // Read the program header table and section header table
    // Move to programTable offset
    fseek(elf_fp, programHeaderTableOffset, SEEK_SET);
    fread(programHeaderTable, programTableEntrySize, numProgramHeader, elf_fp);

    // Move to sectionTable offset
    fseek(elf_fp, sectionHeaderTableOffset, SEEK_SET);
    fread(sectionHeaderTable, sectionTableEntrySize, numSectionHeader, elf_fp);

    // Print elf read result
    printElf(e_ident_peek[EI_CLASS], elfHeader, programHeaderTable, sectionHeaderTable,
             numProgramHeader, numSectionHeader);

    // Clean up
    free(elfHeader);
    free(programHeaderTable);
    free(sectionHeaderTable);
    fclose(elf_fp);

    return 0;
}

void printElf(uint8_t ei_class, void *elfHeader, void *programHeaderTable, void *sectionHeaderTable, 
              uint16_t ph_num, uint16_t sh_num) {
    printElfHeader(ei_class, elfHeader);
    printElfProgramHeader(ei_class, programHeaderTable, ph_num);
    printElfSectionHeader(ei_class, sectionHeaderTable, sh_num);
}

void printElfHeader(uint8_t ei_class, void *elfHeader) {
    if (ei_class == ELFCLASS32) {
        Elf32_Ehdr * header = elfHeader;
        for (int i = 0; i < EI_NIDENT; i++) {
            printf("e_ident[%d] = %hhx\n", i, header->e_ident[i]);
        }
        printf("e_type = %x\n", header->e_type);
        printf("e_machine = %x\n", header->e_machine);
        printf("e_version = %x\n", header->e_version);
        printf("e_entry = %x\n", header->e_entry);
        printf("e_phoff = %x\n", header->e_phoff);
        printf("e_shoff = %x\n", header->e_shoff);
        printf("e_flags = %x\n", header->e_flags);
        printf("e_ehsize = %x\n", header->e_ehsize);
        printf("e_phentsize = %x\n", header->e_phentsize);
        printf("e_phnum = %x\n", header->e_phnum);
        printf("e_shentsize = %x\n", header->e_shentsize);
        printf("e_shnum = %x\n", header->e_shnum);
        printf("e_shstrndx = %x\n", header->e_shstrndx);
    } else if (ei_class == ELFCLASS64) {
        Elf64_Ehdr * header = elfHeader;
        for (int i = 0; i < EI_NIDENT; i++) {
            printf("e_ident[%d] = %hhx\n", i, header->e_ident[i]);
        }
        printf("e_type = %x\n", header->e_type);
        printf("e_machine = %x\n", header->e_machine);
        printf("e_version = %x\n", header->e_version);
        printf("e_entry = %lx\n", header->e_entry);
        printf("e_phoff = %lx\n", header->e_phoff);
        printf("e_shoff = %lx\n", header->e_shoff);
        printf("e_flags = %x\n", header->e_flags);
        printf("e_ehsize = %x\n", header->e_ehsize);
        printf("e_phentsize = %x\n", header->e_phentsize);
        printf("e_phnum = %x\n", header->e_phnum);
        printf("e_shentsize = %x\n", header->e_shentsize);
        printf("e_shnum = %x\n", header->e_shnum);
        printf("e_shstrndx = %x\n", header->e_shstrndx);
    }
}

void printElfProgramHeader(uint8_t ei_class, void *programHeaderTable, uint16_t num) {
    if (ei_class == ELFCLASS32) {
        Elf32_Phdr * entry_ptr = programHeaderTable;
        while (num > 0) {
            printf("p_type = %x ", entry_ptr->p_type);
            printf("p_offset = %x ", entry_ptr->p_offset);
            printf("p_vaddr = %x ", entry_ptr->p_vaddr);
            printf("p_paddr = %x ", entry_ptr->p_paddr);
            printf("p_filesz = %x ", entry_ptr->p_filesz);
            printf("p_memsz = %x ", entry_ptr->p_memsz);
            printf("p_flags = %x ", entry_ptr->p_flags);
            printf("p_align = %x\n", entry_ptr->p_align);

            num--;
            entry_ptr++;
        }
    } else if (ei_class == ELFCLASS64) {
        Elf64_Phdr * entry_ptr = programHeaderTable;
        while (num > 0) {
            printf("p_type = %x ", entry_ptr->p_type);
            printf("p_offset = %lx ", entry_ptr->p_offset);
            printf("p_vaddr = %lx ", entry_ptr->p_vaddr);
            printf("p_paddr = %lx ", entry_ptr->p_paddr);
            printf("p_filesz = %lx ", entry_ptr->p_filesz);
            printf("p_memsz = %lx ", entry_ptr->p_memsz);
            printf("p_flags = %x ", entry_ptr->p_flags);
            printf("p_align = %lx\n", entry_ptr->p_align);

            num--;
            entry_ptr++;
        }
    }
}

void printElfSectionHeader(uint8_t ei_class, void *sectionHeaderTable, uint16_t num) {
    if (ei_class == ELFCLASS32) {
        Elf32_Shdr * entry_ptr = sectionHeaderTable;
        while (num > 0) {
            printf("sh_name = %x ", entry_ptr->sh_name);
            printf("sh_type = %x ", entry_ptr->sh_type);
            printf("sh_flags = %x ", entry_ptr->sh_flags);
            printf("sh_addr = %x ", entry_ptr->sh_addr);
            printf("sh_offset = %x ", entry_ptr->sh_offset);
            printf("sh_size = %x ", entry_ptr->sh_size);
            printf("sh_link = %x ", entry_ptr->sh_link);
            printf("sh_info = %x ", entry_ptr->sh_info);
            printf("sh_addralign = %x ", entry_ptr->sh_addralign);
            printf("sh_entsize = %x\n", entry_ptr->sh_entsize);

            num--;
            entry_ptr++;
        }
    } else if (ei_class == ELFCLASS64) {
        Elf64_Shdr * entry_ptr = sectionHeaderTable;
        while (num > 0) {
            printf("sh_name = %x ", entry_ptr->sh_name);
            printf("sh_type = %x ", entry_ptr->sh_type);
            printf("sh_flags = %lx ", entry_ptr->sh_flags);
            printf("sh_addr = %lx ", entry_ptr->sh_addr);
            printf("sh_offset = %lx ", entry_ptr->sh_offset);
            printf("sh_size = %lx ", entry_ptr->sh_size);
            printf("sh_link = %x ", entry_ptr->sh_link);
            printf("sh_info = %x ", entry_ptr->sh_info);
            printf("sh_addralign = %lx ", entry_ptr->sh_addralign);
            printf("sh_entsize = %lx\n", entry_ptr->sh_entsize);

            num--;
            entry_ptr++;
        }
    }
}
