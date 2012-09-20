"""
This script is based on analysis of herpnet available at:
http://code.google.com/p/malware-lu/wiki/en_analyse_herpnet

The difference of the python scrtip is that this IDAPython
script patches the database in the comments with the decoded strings.
Also, it searcher for all data cross-reference to the encoded strings
and patch those addresses within the decoded strings.

IDB available at:
http://code.google.com/p/malware-lu/source/browse/herpnet/idb/db6779d497cb5e22697106e26eebfaa8.idb

Thanks to the folks from malware-lu for providing IDB and the analysis publicly

Pedro Drimel Neto
pedrodrimel (\at\) gmail (\dot\) com
"""

def decode(str):
	r = ""
	for s in str:
		s = ord(s)
		if (s >= 0x61) and (s <= 0x7a):
			x = ((s - 0x54) % 0x1a) + 0x61
		elif (s >= 0x41) and (s <= 0x5a):
			x = ((s - 0x34) % 0x1a) + 0x41
		else:
			r += chr(s)
			continue
		r += chr(x)
	
	return r
		

def decode_strings(func_name):
	func_addr = LocByName(func_name)
	if func_addr == BADADDR:
		Message("Function %s not found\n" % func_name)
		return None
	
	for xref in XrefsTo(func_addr, 0):
		if xref.type == fl_CN or xref.type == fl_CF:
			addr = GetPrevFixupEA(xref.frm) - 1
			addr = Dfirst(addr)
			str_type = GetStringType(addr)
			str = GetString(addr, -1, str_type)
			str = decode(str)
			print str
			xref2 = DfirstB(addr)
			print 'Addr = 0x%x' % addr
			while xref2 != BADADDR:
				MakeComm(xref2, str)
				xref2 = DnextB(addr, xref2)
			
def main():
	Message("\n")
	decode_strings('decode')
	
if __name__ == '__main__':
	main()
