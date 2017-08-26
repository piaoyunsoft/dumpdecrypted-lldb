#!/usr/bin/python

import lldb
import commands
import optparse
import shlex

def create_dumpdecrypted_options():
    usage = "usage: %prog <options>"
    parser = optparse.OptionParser(prog='dumpdecrypted', usage=usage)
    parser.add_option('-i', '--image', type='string', dest='image', help='dumpdecrypted image name')
    parser.add_option('-s', '--cryptsize', type='int', dest='size', help='crypted size')
    parser.add_option('-f', '--cryptoff', type='int', dest='cryptoff', help='crypted offset')
    parser.add_option('-o', '--output', type='string', dest='output', help='Where to save the output file')
    return parser

def dumpdecrypted(debugger, command, result, internal_dict):
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
            image_load_address = module.GetObjectFileHeaderAddress().load_addr
            print("INFO: image `%s' loaded at <0x%016X>" % (options.image, image_load_address))
            ci = debugger.GetCommandInterpreter()
            res = lldb.SBCommandReturnObject()
            ci.HandleCommand("memory read --force --outfile %s.bin --binary --count %d 0x%016X" % (options.output, options.size, image_load_address + options.cryptoff), res)
            if res.Succeeded():
                print("INFO: %d bytes read as binary" % (options.size))
                print("INFO: convert binary file via dd...")
                result = commands.getoutput('dd seek=%d bs=1 conv=notrunc if=%s.bin of=%s' % (options.cryptoff, options.output, options.output))
                commands.getoutput('rm -f %s.bin' % (options.output))
                print(result)
            else:
                print(res)
            break

def __lldb_init_module(debugger, internal_dict):
    parser = create_dumpdecrypted_options()
    dumpdecrypted.__doc__ = parser.format_help()
    debugger.HandleCommand('command script add -f %s.dumpdecrypted dumpdecrypted' % __name__)
