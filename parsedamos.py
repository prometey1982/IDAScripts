#!/usr/bin/python

import sys

if len(sys.argv) != 2:
    print 'please specify filename'
    exit

f = open(sys.argv[1], "r")
lines = f.readlines()
f.close()

#print 'loaded ' + sys.argv[1] + ' with ' + str(len(lines)) + ' lines'
print '# -*- coding: latin-1 -*-'

for line in lines:

    data = line.split(',')
    if len(data) > 1:
        data[1] = data[1].strip()

        if data[1].startswith('/SPZ'):
            data = line.split(',')
            varname = data[2].strip()
            varcomment = (line[line.find("{")+1 : line.find("}")] )

            temp = line[line.find("}")+1 : -1]
            aftercomment = temp[temp.find("}")+1 : -1]
            dataac = aftercomment.split(',')
            varoffset = int(dataac[2].strip()[1:], 16)

            print("set_name(" + hex(varoffset) +", \"" + varname + "\");")
            if len(varcomment):
                print("set_cmt(" + hex(varoffset) +", \"" + varcomment.replace('"', '\\"') + "\", 1);")


        if data[1].startswith('/SRC'):
            data = line.split(',')
            varname = data[2].strip()
            varcomment = (line[line.find("{")+1 : line.find("}")] )

            temp = line[line.find("}")+1 : -1]
            aftercomment = temp[temp.find("}")+1 : -1]
            dataac = aftercomment.split(',')
            varoffset = int(dataac[1].strip()[1:], 16)

            print("set_name(" + hex(varoffset) +", \"" + varname + "\");")
            if len(varcomment):
                print("set_cmt(" + hex(varoffset) +", \"" + varcomment.replace('"', '\\"') + "\", 1);")


    if line.startswith('/UMP'):
#        /UMP, {}, afnmn, {Bereichsfenster Aussetzer, minimale Drehzahl}, $3830B5, 513, 160, nmot_ub_q40, 3, $FF, K;

        data = line.split(',')

        temp = line[line.find("}")+1 : -1]
        varcomment = (temp[temp.find("{")+1 : temp.find("}")] )

        temp = line[line.find("}")+1 : -1]
        aftercomment = temp[temp.find("}")+1 : -1]
        dataac = aftercomment.split(',')

        varname = data[2].strip()
        varoffset = int(dataac[1].strip()[1:], 16)
        varmask = dataac[6].strip()[1:]

        if varmask == 'FF' or varmask == 'FFFF':
            #print(varname + " | " + hex(varoffset) + " | " + varcomment + " | " + varmask)
            print("set_name(" + hex(varoffset) +", \"" + varname + "\");")
            if len(varcomment):
                print("set_cmt(" + hex(varoffset) +", \"" + varcomment.replace('"', '\\"') + "\", 1);")
            #print(varmask)
        else:
            enumname = "enum_" + str(hex(varoffset))[2:]
            maskstr = hex(int(varmask, 16))
            print("add_enum(-1, \"" + enumname + "\", 0)")
            print("set_enum_bf(get_enum(\"" + enumname + "\"), 1)")
            print("add_enum_member(get_enum(\"" + enumname + "\"), \"" + varname + "\"," + maskstr + ", " + maskstr + ")")
