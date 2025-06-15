#!/usr/bin/env python3

# Copyright (c) 2015-2020 Florent Kermarrec <florent@enjoy-digital.fr>
# Copyright (c) 2016 Tim 'mithro' Ansell <mithro@mithis.com>
# Copyright (c) 2025 Andrew 'bunnie' Huang <bunnie@baochip.com>
# SPDX-License-Identifier: BSD-2-Clause

import os
import time
import argparse

from csr_builder import CSRBuilder
from elftools.elf.elffile import ELFFile

halt_cpu = [
    0x4fffc537,
    0xf00002b7,
    0x00100313,  # top 3 digits are the RGB color
    0x0062a023,
    0xa001a001,
]

def load_elf(host, filename):
    # halt the CPU with a small assembly routine
    write_memory(host, 0x4000_0000, halt_cpu)
    host.comm._flush()
    time.sleep(0.2)
    write_memory(host, reg2addr(host, "ctrl_reset"), 1)
    time.sleep(0.2)

    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        for name in ['.data', '.bss', '.rodata', '.text']:
            section = elf.get_section_by_name(name)
            if section:
                offset = section['sh_offset']
                addr = section['sh_addr']
                size = section['sh_size']

                print(f"Section: {name}")
                print(f"  File offset : 0x{offset:08x}")
                print(f"  Load address: 0x{addr:08x}")
                print(f"  Length      : 0x{size:08x}")

                f.seek(offset)
                if name == '.bss':
                    # this section is just an area to be zero'd and not in file
                    data = bytes(size)
                    if size > 4096:
                        print("WARNING: BSS > 4096, breaks memory layout assumptions")
                else:
                    data = f.read(size)
                words = bytes_to_int32_list(data)

                # default strategy: write from low to high in 128-word chunks
                chunk_size = 128
                total = len(words)
                # Compute number of chunks (ceil division)
                num_chunks = (total + chunk_size - 1) // chunk_size
                word_size = 4  # 32-bit = 4 bytes

                for i in range(num_chunks):
                    # Reverse index: write highest chunk first
                    chunk_index = num_chunks - 1 - i
                    start = chunk_index * chunk_size
                    end = min(start + chunk_size, total)
                    chunk = words[start:end]

                    # Compute target address for this chunk
                    offset = start * word_size
                    target_addr = addr + offset
                    write_memory(host, target_addr, chunk)

                    # verify
                    rbk = host.read(target_addr, len(chunk))
                    min_len = min(len(rbk), len(chunk))
                    for i in range(min_len):
                        a = rbk[i] if i < len(rbk) else "<missing>"
                        b = chunk[i] if i < len(words) else "<missing>"
                        if a != b:
                            print(f"Mismatch at index {i}: rbk[{i}] = {a}, data[{i}] = {b}")

                # write from high to low strategy
                if False:
                    STEP = 128
                    for chunk_index in range(0, len(words), STEP):
                        if chunk_index + STEP < len(words):
                            end_index = chunk_index + STEP
                        else:
                            end_index = len(words)
                        target_addr = addr + chunk_index * 4
                        chunk = words[chunk_index:end_index]
                        write_memory(
                            host,
                            addr    = target_addr,
                            data    = chunk,
                        )

                        # verify
                        rbk = host.read(target_addr, len(chunk))
                        min_len = min(len(rbk), len(chunk))
                        for i in range(min_len):
                            a = rbk[i] if i < len(rbk) else "<missing>"
                            b = chunk[i] if i < len(words) else "<missing>"
                            if a != b:
                                print(f"Mismatch at index {i}: rbk[{i}] = {a}, data[{i}] = {b}")
                # write all at once strategy
                if False:
                    write_memory(host, addr, words)
                    rbk = host.read(addr, len(words))
                    max_len = max(len(rbk), len(words))
                    for i in range(max_len):
                        a = rbk[i] if i < len(rbk) else "<missing>"
                        b = words[i] if i < len(words) else "<missing>"
                        if a != b:
                            print(f"Mismatch at index {i}: rbk[{i}] = {a}, data[{i}] = {b}")
            else:
                print(f"Section {name} not found")
            host.comm._flush()
            time.sleep(0.2)

    # write_memory(host, 0xf00f_0000, 0x0200_0000) # unhalt core
    time.sleep(0.1)


# Remote Client ------------------------------------------------------------------------------------

class LocalClient(CSRBuilder):
    def __init__(self, comm, base_address=0, csr_csv=None, csr_data_width=None, debug=False):
        # If csr_csv set to None and local csr.csv file exists, use it.
        if csr_csv is None and os.path.exists("csr.csv"):
            csr_csv = "csr.csv"
        # If valid csr_csv file found, build the CSRs.
        if csr_csv is not None:
            CSRBuilder.__init__(self, self, csr_csv, csr_data_width)
        # Else if csr_data_width set to None, force to csr_data_width 32-bit.
        elif csr_data_width is None:
            csr_data_width = 32
        self.debug        = debug
        self.binded       = False
        self.base_address = base_address if base_address is not None else 0
        self.comm = comm

    def read(self, addr, length=None, burst="incr"):
        datas = []
        if length:
            datas += self.comm.read(addr, length, burst)
        else:
            datas += [self.comm.read(addr, length, burst)]
        if self.debug:
            for i, data in enumerate(datas):
                print("read 0x{:08x} @ 0x{:08x}".format(data, self.base_address + addr + 4*i))
        return datas[0] if length is None else datas

    def write(self, addr, datas):
        self.comm.write(addr, datas)
        if self.debug:
            for i, data in enumerate(datas):
                print("write 0x{:08x} @ 0x{:08x}".format(data, self.base_address + addr + 4*i))

# Utils --------------------------------------------------------------------------------------------
def dump_identifier(bus):
    fpga_identifier = ""

    for i in range(256):
        c = chr(bus.read(bus.bases.identifier_mem + 4*i) & 0xff)
        fpga_identifier += c
        if c == "\0":
            break

    print(fpga_identifier)

def dump_registers(bus, filter=None, binary=False):
    for name, register in bus.regs.__dict__.items():
        if (filter is None) or filter in name:
            register_value = {
                True  : f"{register.read():032b}",
                False : f"{register.read():08x}",
            }[binary]
            print("0x{:08x} : 0x{} {}".format(register.addr, register_value, name))


def read_memory(bus, addr, length):
    for offset in range(length//4):
        print(f"0x{addr + 4*offset:08x} : 0x{bus.read(addr + 4*offset):08x}")

def write_memory(bus, addr, data):
    bus.write(addr, data)

def reg2addr(host, reg):
    if hasattr(host.regs, reg):
        return getattr(host.regs, reg).addr
    else:
        raise ValueError(f"Register {reg} not present, exiting.")

import struct
def bytes_to_int32_list(byte_data):
    # Pad to multiple of 4 bytes
    padded_len = (len(byte_data) + 3) & ~3
    byte_data += b'\x00' * (padded_len - len(byte_data))

    # Unpack as little-endian 32-bit integers
    return list(struct.unpack('<' + 'I' * (len(byte_data) // 4), byte_data))

# Run ----------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="BIO Loader.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--csr-csv", default="csr.csv",     help="CSR configuration file")
    parser.add_argument("--ident",   action="store_true",   help="Dump SoC identifier.")
    parser.add_argument("--regs",    action="store_true",   help="Dump SoC registers.")
    parser.add_argument("--binary",  action="store_true",   help="Use binary format for displayed values.")
    parser.add_argument("--filter",  default=None,          help="Registers filter (to be used with --regs).")
    parser.add_argument("--read",    default=None,          help="Do a MMAP Read to SoC bus (--read addr/reg).")
    parser.add_argument("--write",   default=None, nargs=2, help="Do a MMAP Write to SoC bus (--write addr/reg data).")
    parser.add_argument("--file",    default=None, nargs=2, metavar=('ADDR', 'FILENAME'), help="[offset] [file] Loads file into offset")
    parser.add_argument("--elf",     default=None,          help="Loads ELF file into device")
    parser.add_argument("--length",  default="4",           help="MMAP access length.")

    # UART arguments
    parser.add_argument("--uart-port",       default=None,           help="Set UART port.", required=True)
    parser.add_argument("--uart-baudrate",   default=1000000,         help="Set UART baudrate.")
    parser.add_argument("--debug",           action="store_true",    help="Enable debug.")

    args = parser.parse_args()
    from comm_uart import CommUART
    if args.uart_port is None:
        print("Need to specify --uart-port, exiting.")
        exit()
    uart_port = args.uart_port
    uart_baudrate = int(float(args.uart_baudrate))
    print("[CommUART] port: {} / baudrate: {} / ".format(uart_port, uart_baudrate), end="")
    comm = CommUART(uart_port, uart_baudrate, debug=args.debug)
    host = LocalClient(comm, csr_csv=args.csr_csv)
    time.sleep(0.5)

    if args.ident:
        dump_identifier(
            host,
        )

    if args.regs:
        dump_registers(
            host,
            filter  = args.filter,
            binary  = args.binary,
        )

    if args.read:
        try:
           addr = int(args.read, 0)
        except ValueError:
            addr = reg2addr(host, args.read)
        read_memory(
            host,
            addr    = addr,
            length  = int(args.length, 0),
        )

    if args.write:
        try:
           addr = int(args.write[0], 0)
        except ValueError:
            addr = reg2addr(host, args.write[0])
        write_memory(
            host,
            addr    = addr,
            data    = int(args.write[1], 0),
        )

    if args.file:
        addr_str, filename = args.file
        address = int(addr_str, 16)  # Convert hex string to int
        time.sleep(0.1)
        write_memory(host, 0xf00f_0000, 0x0002_0000)
        time.sleep(0.1)

        print(f"Address: {address:#x}, File: {filename}")
        with open(filename, 'rb') as f:
            data = f.read()
            words = bytes_to_int32_list(data)
            STEP = 128
            for chunk_index in range(0, len(words), STEP):
                if chunk_index + STEP < len(words):
                    end_index = chunk_index + STEP
                else:
                    end_index = len(words)
                write_memory(
                    host,
                    addr    = address + chunk_index * 4,
                    data    = words[chunk_index:end_index],
                )
        comm._flush()
        time.sleep(0.5)
        time.sleep(0.1)
        write_memory(host, 0xf00f_0000, 0x0200_0000)
        time.sleep(0.1)
        write_memory(host, reg2addr(host, "ctrl_reset"), 1)

    if args.elf:
        filename = args.elf
        print(f"File: {filename}")

        load_elf(host, filename)

        comm._flush()
        time.sleep(0.5)
        write_memory(host, reg2addr(host, "ctrl_reset"), 1)

if __name__ == "__main__":
    main()
