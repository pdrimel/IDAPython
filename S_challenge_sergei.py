"""
This script is based on the file extracted on the challenge posted by Sergei Frankoff <sergei.frankoff@owasp.org>

Thanks Sergei for posting the challenge and letting me post about it.

I might say that my solution to the challenge was not an IDA script, I was lazy then I basically run the
program in gdb and looked in the stack so I could find the decoded answer and then grab the secret key.

After that I realized that was a simple sub by 0xa on the answer but I didn't right way how to
create an IDA script to read the offset and subtract all of them by 0xa and display end result as a string and here it is.

Pedro Drimel Neto
pedrodrimel (\at\) gmail (\dot\) com
"""
			
def main():
	start = AskAddr(0x08048900,'Enter start address of string')
	end = start + (0x4*0x15)
	answer = []
	for ea in range(start, end):
		if Byte(ea) != 0x0:
			answer.append(chr(Byte(ea)-10)) # sub by 0xa
	print ''.join(answer[::-1])
	
if __name__ == '__main__':
	main()
