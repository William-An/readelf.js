const {ELFInfo, EI_INDEX} = require("../readelf.ts");
const fs = require("fs");
const elf_buffer = fs.readFileSync("./test/helloworld.elf");

let elfinfo = new ELFInfo(elf_buffer);