import { assert } from "console";

type integer = number | bigint;

/**
 * Field <-> size mapping for fields in type T
 */
type ObjectFieldSizeMap<T extends object> = FieldSizeMapping<T>[];

type ProgramHeaderTableEntry = {
    p_type: integer;
    p_flags: integer;
    p_offset: integer;
    p_vaddr: integer;
    p_paddr: integer;
    p_filesz: integer;
    p_memsz: integer;
    p_align: integer;
}

type SectionHeaderTableEntry = {
    sh_name: integer;
    sh_type: integer;
    sh_flags: integer;
    sh_addr: integer;
    sh_offset: integer;
    sh_size: integer;
    sh_link: integer;
    sh_info: integer;
    sh_addralign: integer;
    sh_entsize: integer;
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
        this.sectionHeader = new ELFSectionHeader(this.binary, this.bit,
            this.endianness, this.fileHeader.e_shnum, this.fileHeader.e_shoff);
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

    readUIntVariousSize(offset: number, size: number): integer {
        let buf = this.binary;
        let endianness = this.endianness;
        let res: integer = 0;
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
                default:
                    throw RangeError(`Illegal unsigned integer size: ${size}`)
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
                default:
                    throw RangeError(`Illegal unsigned integer size: ${size}`)
            }
        }
        return res;
    }
}

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

/**
 * Type field size info
 */
type FieldSizeMapping<T> = {
    field: keyof T;
    size: number;
}

class ELFProgramHeader extends ELFHeader {
    phTable: Array<ProgramHeaderTableEntry>;
    phEntries: number;
    phoff: integer;
    readonly phEntrySizeMapping32: ObjectFieldSizeMap<ProgramHeaderTableEntry> = [
        { field: "p_type", size: 0x4 },
        { field: "p_offset", size: 0x4 },
        { field: "p_vaddr", size: 0x4 },
        { field: "p_paddr", size: 0x4 },
        { field: "p_filesz", size: 0x4 },
        { field: "p_memsz", size: 0x4 },
        { field: "p_flags", size: 0x4 },
        { field: "p_align", size: 0x4 },
    ];
    readonly phEntrySizeMapping64: ObjectFieldSizeMap<ProgramHeaderTableEntry> = [
        { field: "p_type", size: 0x4 },
        { field: "p_flags", size: 0x4 },
        { field: "p_offset", size: 0x8 },
        { field: "p_vaddr", size: 0x8 },
        { field: "p_paddr", size: 0x8 },
        { field: "p_filesz", size: 0x8 },
        { field: "p_memsz", size: 0x8 },
        { field: "p_align", size: 0x8 },
    ];
    readonly phEntry_size_32 = 0x20;
    readonly phEntry_size_64 = 0x38;


    constructor(binary: Buffer, bit: "32" | "64", endianess: "big" | "little",
        phEntries: number, phoff: number | bigint) {
        super(binary);
        this.bit = bit;
        this.endianness = endianess;
        this.phEntries = phEntries;
        this.phoff = phoff;
        this.phTable = Array<ProgramHeaderTableEntry>(this.phEntries);

        // Fill up table entry from offset
        let offset = this.phoff;
        for (let i = 0; i < this.phEntries; i++) {
            [this.phTable[i], offset] = this.readEntry(Number(offset));
        }
    }

    readEntry(start_offset: number): [ProgramHeaderTableEntry, number] {
        let entry: ProgramHeaderTableEntry = {
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
        let mapping = this.bit === "32" ? this.phEntrySizeMapping32 : this.phEntrySizeMapping64;
        mapping.forEach((mapping) => {
            let field = mapping.field;
            let size = mapping.size;
            entry[field] = this.readUIntVariousSize(offset, size);
            offset += size;
        });

        let diff = offset - start_offset;
        if (this.bit === "32")
            assert(diff === this.phEntry_size_32, `Entry size mismatched! Expect ${this.phEntry_size_32} but got ${diff}`);
        else
            assert(diff === this.phEntry_size_64, `Entry size mismatched! Expect ${this.phEntry_size_64} but got ${diff}`);

        return [entry, offset];
    }
};

class ELFSectionHeader extends ELFHeader {
    shTable: Array<SectionHeaderTableEntry>;
    shEntries: number;
    shoff: integer;
    readonly shEntrySizeMapping32: ObjectFieldSizeMap<SectionHeaderTableEntry> = [
        { field: "sh_name", size: 0x4 },
        { field: "sh_type", size: 0x4 },
        { field: "sh_flags", size: 0x4 },
        { field: "sh_addr", size: 0x4 },
        { field: "sh_offset", size: 0x4 },
        { field: "sh_size", size: 0x4 },
        { field: "sh_link", size: 0x4 },
        { field: "sh_info", size: 0x4 },
        { field: "sh_addralign", size: 0x4 },
        { field: "sh_entsize", size: 0x4 },
    ];
    readonly shEntrySizeMapping64: ObjectFieldSizeMap<SectionHeaderTableEntry> = [
        { field: "sh_name", size: 0x4 },
        { field: "sh_type", size: 0x4 },
        { field: "sh_flags", size: 0x8 },
        { field: "sh_addr", size: 0x8 },
        { field: "sh_offset", size: 0x8 },
        { field: "sh_size", size: 0x8 },
        { field: "sh_link", size: 0x4 },
        { field: "sh_info", size: 0x4 },
        { field: "sh_addralign", size: 0x8 },
        { field: "sh_entsize", size: 0x8 },
    ];
    readonly shEntry_size_32 = 0x28;
    readonly shEntry_size_64 = 0x40;

    constructor(binary: Buffer, bit: "32" | "64", endianess: "big" | "little",
        shEntries: number, shoff: integer) {
        super(binary);
        this.bit = bit;
        this.endianness = endianess;
        this.shEntries = shEntries;
        this.shoff = shoff;
        this.shTable = Array<SectionHeaderTableEntry>(this.shEntries);

        // Fill up table entry from offset
        let offset = this.shoff;
        for (let i = 0; i < this.shEntries; i++) {
            [this.shTable[i], offset] = this.readEntry(Number(offset));
        }
    }

    readEntry(start_offset: number): [SectionHeaderTableEntry, number] {
        let offset = start_offset;
        let entry: SectionHeaderTableEntry = {
            sh_name: 0x0,
            sh_type: 0x0,
            sh_flags: 0x0,
            sh_addr: 0x0,
            sh_offset: 0x0,
            sh_size: 0x0,
            sh_link: 0x0,
            sh_info: 0x0,
            sh_addralign: 0x0,
            sh_entsize: 0x0,
        };

        let mapping = this.bit === "32" ? this.shEntrySizeMapping32 : this.shEntrySizeMapping64;
        mapping.forEach((mapping) => {
            let field = mapping.field;
            let size = mapping.size;
            entry[field] = this.readUIntVariousSize(offset, size);
            offset += size;
        });

        let diff = offset - start_offset;
        if (this.bit === "32")
            assert(diff === this.shEntry_size_32, `Entry size mismatched! Expect ${this.shEntry_size_32} but got ${diff}`);
        else
            assert(diff === this.shEntry_size_64, `Entry size mismatched! Expect ${this.shEntry_size_64} but got ${diff}`);

        return [entry, offset];
    }
};

module.exports = {
    ELFInfo,
    EI_INDEX
}