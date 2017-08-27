#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import struct

def create_dumpdecrypted_options():
    usage = "usage: %prog <options>"
    parser = optparse.OptionParser(prog='dumpdecrypted', usage=usage)
    parser.add_option('-i', '--image', type='string', dest='image', help='dumpdecrypted image name')
    parser.add_option('-o', '--output', type='string', dest='output', help='Where to save the output file')
    return parser

def dumpdecrypted(debugger, command, result, internal_dict):
    # MachO Magic Constants
    MH_MAGIC = 0xFEEDFACE
    MH_CIGAM = 0xCEFAEDFE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE
    LC_ENCRYPTION_INFO_64 = 0x2C
    LC_ENCRYPTION_INFO = 0x21
    MACHO_HEADER_SIZE = 28
    MACHO_HEADER_64_SIZE = 32
    
    command_list = shlex.split(command)
    
    # Parse the options
    parser = create_dumpdecrypted_options()
    try:
        (options, args) = parser.parse_args(command_list)
    except:
        result.SetError("Option parsing failed")
        return
    
    target = debugger.GetSelectedTarget()
    for module in target.modules:
        if module.file.basename == options.image:
            image_load_address = module.GetObjectFileHeaderAddress().GetLoadAddress(target)
            print("INFO: image `%s' loaded at <0x%016X>" % (options.image, image_load_address))

            # read magic
            mach_header_size = MACHO_HEADER_SIZE
            encryption_info_cmd = LC_ENCRYPTION_INFO
            encryption_info_description = "LC_ENCRYPTION_INFO"
            
            process = target.GetProcess();
            read_res = lldb.SBError()
            macho_memory = process.ReadMemory(image_load_address, 24, read_res)
            if read_res.Success():
                # endian
                magic, = struct.unpack("<I", macho_memory[0:4])
                if magic == MH_MAGIC or magic == MH_MAGIC_64:
                    prefix = "<"
                elif magic == MH_CIGAM or magic == MH_CIGAM_64:
                    prefix = ">"
                else:
                    raise Exception("magic wrong")

                # 64 bit
                if magic == MH_MAGIC_64 or magic == MH_CIGAM_64:
                    mach_header_size = MACHO_HEADER_64_SIZE
                    encryption_info_cmd = LC_ENCRYPTION_INFO_64
                    encryption_info_description = "LC_ENCRYPTION_INFO_64"

                # read load_command
                ncmds,sizecmds = struct.unpack(prefix + "2I", macho_memory[16:24])
                macho_memory = process.ReadMemory(image_load_address, sizecmds, read_res)
                cryptoffset = 0
                cryptsize = 0
                cryptid = 0
                load_command_start = mach_header_size
                for i in range(ncmds):
                    cmd, cmdsize = struct.unpack(prefix + "2I", macho_memory[load_command_start:load_command_start+8])
                    if cmd == encryption_info_cmd:
                        print("INFO: found %s" % (encryption_info_description))
                        load_command_start += 8
                        cryptoffset, cryptsize, cryptid = struct.unpack(prefix + "3I", macho_memory[load_command_start:load_command_start+12])
                        print("INFO: cryptoffset: %d\n      cryptsize:%d\n      cryptid: %d" % (cryptoffset, cryptsize, cryptid))
                        break
                    else:
                        load_command_start += cmdsize

                ci = debugger.GetCommandInterpreter()
                res = lldb.SBCommandReturnObject()
                ci.HandleCommand("memory read --force --outfile %s.bin --binary --count %d 0x%016X" % (options.output, cryptsize, image_load_address + cryptoffset), res)
                if res.Succeeded():
                    print("INFO: %d bytes read as binary" % (cryptsize))
                    print("INFO: convert binary file via dd...")
                    result = commands.getoutput('dd seek=%d bs=1 conv=notrunc if=%s.bin of=%s' % (cryptoffset, options.output, options.output))
                    commands.getoutput('rm -f %s.bin' % (options.output))
                    print(result)
                else:
                    print(res)
            else:
                print(read_res)
            break

def __lldb_init_module(debugger, internal_dict):
    parser = create_dumpdecrypted_options()
    dumpdecrypted.__doc__ = parser.format_help()
    debugger.HandleCommand('command script add -f %s.dumpdecrypted dumpdecrypted' % __name__)
