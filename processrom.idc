#include <idc.idc>

static processrom(min, max)
{
	if (min > 0)
		min = min - 1;
        auto curaddr;
	curaddr = FindUnexplored(min, SEARCH_DOWN);
	while(curaddr < max) {
		if(MakeFunction(curaddr, BADADDR))
			MakeCode(curaddr);
		curaddr = FindUnexplored(curaddr, SEARCH_DOWN);
	}
}

static definecode(min, max)
{
	if (min > 0)
		min = min - 1;
        auto curaddr;
	curaddr = FindUnexplored(min, SEARCH_DOWN);
	while(curaddr < max) {
		MakeCode(curaddr);
		curaddr = FindUnexplored(curaddr, SEARCH_DOWN);
	}
}

static definefunc(min, max)
{
	if (min > 0)
		min = min - 1;
        auto curaddr;
	curaddr = FindCode(min, SEARCH_DOWN);
	while(curaddr < max) {
		if(MakeFunction(curaddr, BADADDR))
			MakeCode(curaddr);
		curaddr = FindCode(curaddr, SEARCH_DOWN);
	}
}

static makexref(from_addr)
{
	auto curaddr;
        curaddr = ScreenEA();
	AddCodeXref(curaddr, from_addr, XREF_USER);
        auto name = sprintf("0x%X", from_addr);
	MakeComm(curaddr, name);
}

static makexref(curaddr)
{
	auto prevaddr;
	auto from_addr;
	auto is_ok = 0;
	auto i;
	prevaddr = PrevHead(curaddr, 0);
	for(i = 0; i < 2; ++i) {
		auto optype = get_operand_type(curaddr, i);
		auto local_addr = get_operand_value(curaddr, i);
		msg("local addr 0x%X, op_type %d\n", local_addr, optype);
		if(optype == o_mem) {
			from_addr = local_addr;
			is_ok = 1;
		}
		else if(optype == o_displ) {
			auto prev_instr = print_insn_mnem(prevaddr);
			if(prev_instr == "extp") {
				from_addr = get_operand_value(prevaddr, 0) * 0x4000 + local_addr;
				is_ok = 1;
			} 
			else if(local_addr & 0x8000 && local_addr & 0x4000) {
				from_addr = get_sreg(curaddr, "DPP3") * 0x4000 + local_addr - 0xC000;
				is_ok = 1;
			}			
			else if(local_addr & 0x8000) {
				from_addr = get_sreg(curaddr, "DPP2") * 0x4000 + local_addr - 0x8000;
				is_ok = 1;
			}
			else if(local_addr & 0x4000) {
				from_addr = get_sreg(curaddr, "DPP1") * 0x4000 + local_addr - 0x4000;
				is_ok = 1;
			}
			else {
				from_addr = get_sreg(curaddr, "DPP0") * 0x4000 + local_addr;
				is_ok = 1;
			}
		}
		if(is_ok)
			break;
			
        }
	msg("0x%X\n", from_addr);
	if(!is_ok)
		return;
	AddCodeXref(curaddr, from_addr, XREF_USER);
        auto name = sprintf("0x%X", from_addr);
	MakeComm(curaddr, name);
}

static makexrefauto()
{
	makexref(ScreenEA());
}

static replacewithxref(to_find, min, max)
{
auto addr = min;
min = -1;
while(addr <= max)
{
    addr = FindText(addr, SEARCH_DOWN, 100000, 0, to_find);
    if(addr < max && addr > min)
    {
        op_hex(addr, 0);
        op_hex(addr, 1);
        op_hex(addr, 2);
        makexref(addr);
	min = addr;
	++addr;
    }
    else
    {
        break;
    }
}
}

static printxrefauto()
{
	auto curaddr;
	auto prevaddr;
	auto from_addr;
	auto is_ok = 0;
	auto i;
        curaddr = ScreenEA();
	prevaddr = PrevHead(curaddr, 0);
	for(i = 0; i < 2; ++i) {
		auto optype = get_operand_type(curaddr, i);
		auto local_addr = get_operand_value(curaddr, i);
		msg("local addr 0x%X, op_type %d\n", local_addr, optype);
		if(optype == o_mem) {
			from_addr = local_addr;
			is_ok = 1;
		}
		else if(optype == o_displ) {
			auto prev_instr = print_insn_mnem(prevaddr);
			if(prev_instr == "extp") {
				from_addr = get_operand_value(prevaddr, 0) * 0x4000 + local_addr;
				is_ok = 1;
			} 
			else if(local_addr & 0x8000 && local_addr & 0x4000) {
				from_addr = get_sreg(curaddr, "DPP3") * 0x4000 + local_addr - 0xC000;
				is_ok = 1;
			}			
			else if(local_addr & 0x8000) {
				from_addr = get_sreg(curaddr, "DPP2") * 0x4000 + local_addr - 0x8000;
				is_ok = 1;
			}
			else if(local_addr & 0x4000) {
				from_addr = get_sreg(curaddr, "DPP1") * 0x4000 + local_addr - 0x4000;
				is_ok = 1;
			}
			else {
				from_addr = get_sreg(curaddr, "DPP0") * 0x4000 + local_addr;
				is_ok = 1;
			}
		}
		if(is_ok)
			break;
			
        }
	msg("0x%X\n", from_addr);
}
