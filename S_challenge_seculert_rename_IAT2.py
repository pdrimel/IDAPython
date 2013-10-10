#!/usr/bin/env python
"""
This is the second script which aids unpack and automatically rename functios from sample 177449d28ca4e0dad76375fe05012edbb18b0439

pedrodrimel *atsign* gmail\(dot\)com
"""

def main():

	new_block = ScreenEA() - 0x46
	new_ep2 = new_block + 0x1704
	RunTo(new_ep2)
	GetDebuggerEvent(WFNE_SUSP, -1)
	
	start = new_block + 0xcc
	end = new_block + 0x298
	while (start <= end):
		print 'entrou no while'
		MakeDword(start)
		start += 0x4
	start = new_block + 0xcc
	while start <= end:
		name = Name(Dword(start))
		idx = name.find("_")
		dllname = name[:idx]
		if dllname == 'ws2':
			idx = idx + 3
		funcname = name[idx+1:]
		if MakeNameEx(start, funcname, SN_CHECK|SN_NOWARN) == 0:
			print 'ERROR MakeNameEx for %s' % funcname
		start += 0x4
	
if __name__ == '__main__':
	main()
