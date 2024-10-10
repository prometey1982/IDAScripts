import idc
import idaapi

def processrom(min, max):
	if min > 0:
		min = min - 1
	curaddr = idc.find_unknown(min, idc.SEARCH_DOWN)
	while curaddr < max:
		if idc.add_func(curaddr) != True:
			idc.create_insn(curaddr)
		curaddr = idc.find_unknown(curaddr, idc.SEARCH_DOWN)

	return

def makedata(min, max, flags, size, tid):
	curaddr = min
	while curaddr < max:
		idc.del_items(curaddr, size, idaapi.DELIT_SIMPLE)
		idc.create_data(curaddr, flags, size, tid)
		curaddr += size

	return

def a2l(filename):
	lastvarname = ""
	lastaddress = ""
	with open(filename) as fp:
		f = fp.read()
		measurements = f.split("/begin MEASUREMENT")
		measurements.pop(0)
		print("Found: %d measurement(s)" % len(measurements))
		for m in measurements:
			namefound = 0
			addrfound = 0
			name = ""
			addr = ""
			is_enum = False
			bit_mask = 0
			for l in m.split("\n"):
				l = l.strip()
				if (len(l) > 0):
					if (namefound == 0):
						name = l
						namefound = 1
					elif (l.startswith("BIT_MASK")):
                                                is_enum = True
                                                bit_mask = int(l.split(" ")[1], 16)
					elif (l.startswith("ECU_ADDRESS")):
						addr = l[12:]
						addrfound = 1
						break
			if (addrfound != 1):
				print("ERROR")
			elif (is_enum):
				enum_name = "enum_" + addr[2:]
				enum_id = idc.get_enum(enum_name)
				if (enum_id == 4294967295):
					enum_id = idc.add_enum(-1, enum_name, 0)
					idc.op_enum(int(addr, 0), -1, enum_id, 0)
					idc.set_name(int(addr, 0), "", 0) 
				if (not idc.is_bf(enum_id)):
					idc.set_enum_bf(enum_id, 1)
				idc.add_enum_member(enum_id, name, bit_mask, bit_mask)
			else:
				idc.del_items(int(addr, 0), 1, idaapi.DELIT_SIMPLE)
				idc.set_name(int(addr, 0), name, 1)
		characteristics = f.split("/begin CHARACTERISTIC")
		characteristics.pop(0)
		print("Found: %d characteristics(s)" % len(characteristics))
		for m in characteristics:
			namefound = 0
			addrfound = 0
			name = ""
			addr = ""
			is_enum = False
			bit_mask = 0
			for l in m.split("\n"):
				l = l.strip()
				if (len(l) > 0):
					if (namefound == 0):
						name = l
						namefound = 1
					elif (l.startswith("0x1C")):
						addr = l
						print(addr)
						addrfound = 1
						break
			if (addrfound != 1):
				print("ERROR", name)
			else:
				print("addr", addr)
				idc.del_items(int(addr, 0), 1, idaapi.DELIT_SIMPLE)
				idc.set_name(int(addr, 0), name, 1)
	return
