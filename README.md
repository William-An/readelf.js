# readelf.js
[![Node.js CI](https://github.com/William-An/readelf.js/actions/workflows/node.js.yml/badge.svg)](https://github.com/William-An/readelf.js/actions/workflows/node.js.yml)

A javascript ELF file reader.

## Install

```shell
npm install readelf.js
```

## Quick Start

This package accepts an elf file stored in `Buffer` and parse the file header, program header, and section header according to the ELF specification. An example usage:

```javascript
const {ELFInfo} = require("readelf.ts");
const fs = require("fs");

// elf Buffer
const elf_buffer = fs.readFileSync("./test/test_progs/helloworld.elf");

// Parse elf file
let elfinfo = new ELFInfo(elf_buffer);
```

`ELFInfo` is the top level structure holding elf information, it has the following field:

```javascript
bit: "32" | "64";                   // 32/64-bit info
endianness: "little" | "big";       // Endianness info
fileHeader: ELFFileHeader;          // ELF file header
progHeader: ELFProgramHeader;       // ELF program header  
sectionHeader: ELFSectionHeader;    // ELF section header
readonly binary: Buffer;            // Reference to the elf binary buffer
```

`ELFFileHeader` contains the fields of file header.

`ELFProgramHeader` contains a program header table stored as array. Each entry in this table corresponds to a program header.

`ELFSectionHeader` similarly describes the section headers, with a table storing all the entries of section headers.
