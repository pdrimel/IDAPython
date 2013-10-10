#!/usr/bin/env python
"""
This is the first script which aids unpack and automatically rename functios from sample 177449d28ca4e0dad76375fe05012edbb18b0439

After execute this script, press F9 twice (let exception handler executes) and then execute the second script

pedrodrimel *atsign* gmail\(dot\)com
"""

def main():

	addr = 0x40be0a
	addr2 = 0x40be39
	RunTo(addr)
	GetDebuggerEvent(WFNE_SUSP, -1)	
	new_block = GetRegValue('eax')
	
	new_ep = new_block + 0x46
	RunTo(addr2)
	GetDebuggerEvent(WFNE_SUSP, -1)	
	MakeCode(new_ep)
	AddBpt(new_ep)
	
if __name__ == '__main__':
	main()
