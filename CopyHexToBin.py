# coding: utf-8
import ida_kernwin
import ida_loader
import idautils
import idaapi
import idc
from idc import *

def mHex(addr, rang):
    
    addr = hex(addr).upper().rstrip('L').lstrip('0X')
    
    if len(addr) < rang:
        
        addr = addr.zfill(rang)
            
    return addr

def LoadHexToBin():

    #ida_kernwin.msg_clear()
 
    filename = ida_kernwin.ask_file(0, "*.h86", "Открыть файл ...")
    
    if not filename:
        return
        
    try:
        f = open(filename, 'r+')
        
    except:
        print('[!] Ошибка открытия файла.')
        return
    
    segment = '0x00'
    lenhex  = 0
    type    = 0
    addr    = 0
    value   = 0
    pADDR   = 0
    pos     = 0    
    
    for line in f:
        
        if line.startswith(":"): 
            
            lenhex = int(line[1:3], 16)*2
            type   = int(line[7:9], 16)
            
            if type == 4:
                
                segment = '0x'+line[11:13]
                
            else:
                
                pos = 0
                addr = int(line[3:7], 16)
                
                for hexpos in range(9, 9 + lenhex, 2):
                    
                    value = line[hexpos : hexpos + 2]
                    pADDR = segment+mHex(addr+pos, 4)
                    pos += 1    
                    
                    patch_byte(int(pADDR, 16), 0)
                    
                    if patch_byte(int(pADDR, 16), int(value, 16)):
                         
                        print (pADDR + ' <- 0x' + value) 
     
    f.close()
    

#------------------------------------------------------------------------
def main(): 
  
  # set 'loading idc file' mode
#  idc.SetCharPrm(INF_GENFLAGS, ~INFFL_NOUSER|INFFL_LOADIDC|GetCharPrm(INF_GENFLAGS))
    
  LoadHexToBin();
  
  # clear 'loading idc file' mode
#  idc.SetCharPrm(INF_GENFLAGS, INFFL_NOUSER|~INFFL_LOADIDC&GetCharPrm(INF_GENFLAGS))
  
  
# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()