doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()
adr = doc.getCurrentAddress()

val = int(doc.ask("Return Value:"))

def ip(v, s):
	return ((v << s) & 0xff)

seg.writeByte(adr, 0xb8)
seg.writeByte(adr + 1, ip(val, 0))
seg.writeByte(adr + 2, ip(val, 8))
seg.writeByte(adr + 3, ip(val, 16))
seg.writeByte(adr + 4, ip(val, 24))
seg.writeByte(adr + 5, 0x5d)
seg.writeByte(adr + 6, 0xc3)

seg.markAsCode(adr)

while adr > seg.getStartingAddress():
	if seg.readByte(adr) == 0x55 and (seg.readByte(adr + 1) == 0x89 or seg.readByte(adr + 1) == 0x48):
		seg.markAsProcedure(adr)
		break
	else:
		adr = adr - 1
