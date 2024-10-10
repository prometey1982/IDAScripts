import idaapi
import idautils
import ida_bytes
import idc
import ida_kernwin

def get_segment_by_name(segment_name):
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == segment_name:
            return seg
    return None


def is_wildcard_operand(op):
    return op.type in {idaapi.o_mem, idaapi.o_imm, idaapi.o_displ, idaapi.o_phrase}


def bytes_to_pattern_with_selective_wildcards(start_ea, end_ea):
    pattern = []
    ea = start_ea

    while ea < end_ea:
        insn = idaapi.insn_t()
        
        # Decode the instruction at the current address
        if idaapi.decode_insn(insn, ea):
            # Get the byte sequence for the current instruction
            insn_size = insn.size
            for i in range(insn_size):
                byte = ida_bytes.get_byte(ea + i)

                # Handle the instruction's operand specifically
                if insn.size == 4 and (i == 2 or i == 3):  # Last two bytes for 4-byte instruction
                    pattern.append("??")
                else:
                    pattern.append("{:02X}".format(byte))
            
            ea += insn_size
        else:
            # In case of a decoding failure, break the loop
            break

    # Check if the entire pattern is made of wildcards, ignore if true
    if all(byte == '??' for byte in pattern):
        return None

    return " ".join(pattern)


def generate_patterns_for_variable_in_segment(variable_name, segment_name):
    seg_start = get_segment_by_name(segment_name)
    if seg_start is None:
        print(f"Segment '{segment_name}' not found.")
        return
    seg_end = idc.get_segm_end(seg_start)

    variable_address = idc.get_name_ea_simple(variable_name)
    if variable_address == idc.BADADDR:
        print(f"Could not find variable '{variable_name}'")
        return

    print(f"Variable '{variable_name}' found at address: {hex(variable_address)}")

    # Search for all instructions referencing the variable within the segment
    for ref_ea in idautils.DataRefsTo(variable_address):
        if seg_start <= ref_ea < seg_end:  # Filter by segment
            disasm_line = idc.generate_disasm_line(ref_ea, 0)

            # Get 5 instructions before and after the reference to the variable
            pattern_instructions = []
            instruction_count = 5
            
            # Load 5 instructions before the reference
            ea = ref_ea
            while instruction_count > 0 and ea > seg_start:
                ea = idc.prev_head(ea)  # Get the previous instruction head
                if ea != idc.BADADDR:
                    pattern_instructions.insert(0, ea)
                    instruction_count -= 1

            # Reset count and load 5 instructions after the reference
            ea = ref_ea
            instruction_count = 5
            while instruction_count > 0 and ea < seg_end:
                pattern_instructions.append(ea)
                ea = idc.next_head(ea)
                if ea == idc.BADADDR:
                    break
                instruction_count -= 1

            # Generate pattern for the loaded instructions
            wildcard_pattern = ""
            for instruction_ea in pattern_instructions:
                wildcard_pattern_part = bytes_to_pattern_with_selective_wildcards(instruction_ea, instruction_ea + 1)
                if wildcard_pattern_part is not None:
                    wildcard_pattern += wildcard_pattern_part + " "

            if wildcard_pattern.strip():  # Only print if the pattern has non-wildcard bytes
                print(f"Usage of '{variable_name}' found at {hex(ref_ea)}: {disasm_line}")
                print(f"Generated pattern: {wildcard_pattern.strip()}\n")


def main():
    print("\n" * 20)
    print("Clearing console...")

    segment_name = ida_kernwin.ask_str("", 0, "Enter the segment name (e.g., 'seg003'):")
    
    if segment_name:
        variable_name = ida_kernwin.ask_str("", 0, "Enter the variable name to find patterns for:")
        
        if variable_name:
            generate_patterns_for_variable_in_segment(variable_name, segment_name)
        else:
            print("No variable name provided.")
    else:
        print("No segment name provided.")


main()
