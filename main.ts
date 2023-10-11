import { assert } from "console";

class ELFInfo {
    bit: "32" | "64";
    endianness: "little" | "big";
    fileHeader: ELFFileHeader;
    progHeader: ELFProgramHeader;
    sectionHeader: ELFSectionHeader;
    readonly binary: Buffer;


    constructor(binary: Buffer) {
        this.binary = binary;
        this.fileHeader = new ELFFileHeader(this.binary);
        this.bit = this.fileHeader.bit;
        this.endianness = this.fileHeader.endianness
        this.progHeader = new ELFProgramHeader(this.binary, this.bit, this.endianness, 
            this.fileHeader.e_phnum, this.fileHeader.e_phoff);
        this.sectionHeader = new ELFSectionHeader();
    }
};

class ELFHeader {
    readonly binary: Buffer;
    bit: "32" | "64";
    endianness: "big" | "little";

    constructor(binary: Buffer) {
        this.binary = binary;
        this.bit = "32";
        this.endianness = "little";
    }

    readUIntVariousSize(offset: number, size: 1 | 2 | 4 | 8): number | bigint {
        let buf = this.binary;
        let endianness = this.endianness;
        let res: number | bigint = 0;
        if (endianness === "big") {
            switch (size) {
                case 1:
                    res = buf.readUInt8(offset);
                    break;
                case 2:
                    res = buf.readUInt16BE(offset);
                    break;
                case 4:
                    res = buf.readUInt32BE(offset);
                    break;
                case 8:
                    res = buf.readBigUInt64BE(offset);
                    break;
            }
        } else {
            switch (size) {
                case 1:
                    res = buf.readUInt8(offset);
                    break;
                case 2:
                    res = buf.readUInt16LE(offset);
                    break;
                case 4:
                    res = buf.readUInt32LE(offset);
                    break;
                case 8:
                    res = buf.readBigUInt64LE(offset);
                    break;
            }
        }
        return res;
    }
}

/**
 * Index enum for elf file header
 */
export enum EI_INDEX {
    EI_MAG0 = 0,
    EI_MAG1,
    EI_MAG2,
    EI_MAG3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    EI_OSABIT,
    EI_ABIVERSION,
    EI_PAD,
    EI_PAD0 = EI_PAD,
    EI_PAD1,
    EI_PAD2,
    EI_PAD3,
    EI_PAD4,
    EI_PAD5,
    EI_PAD6,
};

class ELFFileHeader extends ELFHeader {
    readonly e_ident_size = 0x10;
    readonly e_type_size = 0x2;
    readonly e_machine_size = 0x2;
    readonly e_version_size = 0x4;
    // 64-bit will double the 32-bit size here
    readonly e_entry_size_32 = 0x4;
    readonly e_phoff_size_32 = 0x4;
    readonly e_shoff_size_32 = 0x4;
    readonly e_entry_size_64 = 0x8;
    readonly e_phoff_size_64 = 0x8;
    readonly e_shoff_size_64 = 0x8;
    // end different sizes for 64/32-bit
    readonly e_flags_size = 0x4;
    readonly e_ehsize_size = 0x2;
    readonly e_phentsize_size = 0x2;
    readonly e_phnum_size = 0x2;
    readonly e_shentsize_size = 0x2;
    readonly e_shnum_size = 0x2;
    readonly e_shstrndx_size = 0x2;

    e_ident: Buffer;
    e_type: number;
    e_machine: number;
    e_version: number;
    e_entry: number | bigint;
    e_phoff: number | bigint;
    e_shoff: number | bigint;
    e_flags: number;
    e_ehsize: number;
    e_phentsize: number;
    e_phnum: number;
    e_shentsize: number;
    e_shnum: number;
    e_shstrndx: number;

    constructor(binary: Buffer) {
        super(binary);

        // Construct all fields inside constructor
        let offset = 0;
        this.e_ident = this.binary.subarray(offset, this.e_ident_size);

        // Get bit and endianness info
        let bit_raw = this.e_ident[EI_INDEX.EI_CLASS];
        let endianness_raw = this.e_ident[EI_INDEX.EI_DATA];
        if (bit_raw === 1)
            this.bit = "32";
        else if (bit_raw === 2)
            this.bit = "64";
        else
            throw Error(`Invalid bit info byte: ${bit_raw}`);
        if (endianness_raw === 1)
            this.endianness = "little";
        else if (endianness_raw === 2)
            this.endianness = "big";
        else
            throw Error(`Invalid endianness info byte: ${endianness_raw}`);

        // Parse rest of the elf header
        offset += this.e_ident_size;
        this.e_type = this.readUIntVariousSize(offset, this.e_type_size) as number;
        offset += this.e_type_size;
        this.e_machine = this.readUIntVariousSize(offset, this.e_machine_size) as number;
        offset += this.e_machine_size;
        this.e_version = this.readUIntVariousSize(offset, this.e_version_size) as number;
        offset += this.e_version_size;
        let e_entry_size: 4 | 8 = this.bit == "32" ? this.e_entry_size_32 : this.e_entry_size_64;
        this.e_entry = this.readUIntVariousSize(offset, e_entry_size);
        offset += e_entry_size
        let e_phoff_size: 4 | 8 = this.bit == "32" ? this.e_phoff_size_32 : this.e_phoff_size_64;
        this.e_phoff = this.readUIntVariousSize(offset, e_phoff_size);
        offset += e_phoff_size
        let e_shoff_size: 4 | 8 = this.bit == "32" ? this.e_shoff_size_32 : this.e_shoff_size_64;
        this.e_shoff = this.readUIntVariousSize(offset, e_shoff_size);
        offset += e_shoff_size
        this.e_flags = this.readUIntVariousSize(offset, this.e_flags_size) as number;
        offset += this.e_flags_size;
        this.e_ehsize = this.readUIntVariousSize(offset, this.e_ehsize_size) as number;
        offset += this.e_ehsize_size;
        this.e_phentsize = this.readUIntVariousSize(offset, this.e_phentsize_size) as number;
        offset += this.e_phentsize_size;
        this.e_phnum = this.readUIntVariousSize(offset, this.e_phnum_size) as number;
        offset += this.e_phnum_size;
        this.e_shentsize = this.readUIntVariousSize(offset, this.e_shentsize_size) as number;
        offset += this.e_shentsize_size;
        this.e_shnum = this.readUIntVariousSize(offset, this.e_shnum_size) as number;
        offset += this.e_shnum_size;
        this.e_shstrndx = this.readUIntVariousSize(offset, this.e_shstrndx_size) as number;
        offset += this.e_shstrndx_size;

        // Check if size info matches
        if (offset !== this.e_ehsize)
            throw Error(`Header size mismatched with what is in the header! Header has ${this.e_ehsize} but actually is ${offset}!`);
    }
};

type phTableEntry = {
    p_type: number;
    p_flags: number;
    p_offset: number | bigint;
    p_vaddr: number | bigint;
    p_paddr: number | bigint;
    p_filesz: number | bigint;
    p_memsz: number | bigint;
    p_align: number | bigint;
}

class ELFProgramHeader extends ELFHeader {
    phTable: Array<phTableEntry>;
    phEntries: number;
    phoff: number | bigint;
    readonly phEntry_size_32 = 0x20;
    readonly phEntry_size_64 = 0x38;
    readonly p_type_size = 0x4;
    readonly p_flags_size = 0x4;
    readonly p_offset_size_32 = 0x4;
    readonly p_vaddr_size_32 = 0x4;
    readonly p_paddr_size_32 = 0x4;
    readonly p_filesz_size_32 = 0x4;
    readonly p_memsz_size_32 = 0x4;
    readonly p_align_size_32 = 0x4;
    readonly p_offset_size_64 = 0x8;
    readonly p_vaddr_size_64 = 0x8;
    readonly p_paddr_size_64 = 0x8;
    readonly p_filesz_size_64 = 0x8;
    readonly p_memsz_size_64 = 0x8;
    readonly p_align_size_64 = 0x8;


    constructor(binary: Buffer, bit: "32" | "64", endianess: "big" | "little",
        phEntries: number, phoff: number | bigint) {
        super(binary);
        this.bit = bit;
        this.endianness = endianess;
        this.phEntries = phEntries;
        this.phoff = phoff;
        this.phTable = Array<phTableEntry>(this.phEntries);

        // Fill up table entry from offset
        let offset = this.phoff;
        for (let i = 0; i < this.phEntries; i++) {
            [this.phTable[i], offset] = this.readEntry(Number(offset));
        }
    }

    readEntry(start_offset: number): [phTableEntry, number] {
        let entry: phTableEntry = {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        };

        // Read 1 entry from binary with offset 
        let offset = start_offset;
        entry.p_type = this.readUIntVariousSize(offset, this.p_type_size) as number;
        offset += this.p_type_size;
        if (this.bit === "32") {
            // 32-bit arch
            entry.p_offset = this.readUIntVariousSize(offset, this.p_offset_size_32);
            offset += this.p_offset_size_32;
            entry.p_vaddr = this.readUIntVariousSize(offset, this.p_vaddr_size_32);
            offset += this.p_vaddr_size_32;
            entry.p_paddr = this.readUIntVariousSize(offset, this.p_paddr_size_32);
            offset += this.p_paddr_size_32;
            entry.p_filesz = this.readUIntVariousSize(offset, this.p_filesz_size_32);
            offset += this.p_filesz_size_32;
            entry.p_memsz = this.readUIntVariousSize(offset, this.p_memsz_size_32);
            offset += this.p_memsz_size_32;
            entry.p_flags = this.readUIntVariousSize(offset, this.p_flags_size) as number;
            offset += this.p_flags_size;
            entry.p_align = this.readUIntVariousSize(offset, this.p_align_size_32);
            offset += this.p_align_size_32;

            // Check if size info matches
            if (offset - start_offset !== this.phEntry_size_32)
                throw Error(`Program header entry size mismatched! file header has ${this.phEntry_size_32} but actually is ${offset - start_offset}!`);
        } else {
            // 64-bit arch
            entry.p_flags = this.readUIntVariousSize(offset, this.p_flags_size) as number;
            offset += this.p_flags_size;
            entry.p_offset = this.readUIntVariousSize(offset, this.p_offset_size_64);
            offset += this.p_offset_size_64;
            entry.p_vaddr = this.readUIntVariousSize(offset, this.p_vaddr_size_64);
            offset += this.p_vaddr_size_64;
            entry.p_paddr = this.readUIntVariousSize(offset, this.p_paddr_size_64);
            offset += this.p_paddr_size_64;
            entry.p_filesz = this.readUIntVariousSize(offset, this.p_filesz_size_64);
            offset += this.p_filesz_size_64;
            entry.p_memsz = this.readUIntVariousSize(offset, this.p_memsz_size_64);
            offset += this.p_memsz_size_64;
            entry.p_align = this.readUIntVariousSize(offset, this.p_align_size_64);
            offset += this.p_align_size_64;
            
            // Check if size info matches
            if (offset - start_offset !== this.phEntry_size_64)
                throw Error(`Program header entry size mismatched! file header has ${this.phEntry_size_64} but actually is ${offset - start_offset}!`);
        }

        return [entry, offset];
    }
};

class ELFSectionHeader {
};

module.exports = {
    ELFInfo,
    EI_INDEX
}