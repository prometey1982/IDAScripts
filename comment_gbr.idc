#include <idc.idc>

static comment_text(to_find, to_addr)
{
        auto addr = 0;
        auto name = NameEx(BADADDR, to_addr);
	name = "%s 0x%X" % (name, to_addr);
        while(addr <= 0x80000)
        {
		addr = FindText(addr, SEARCH_DOWN, 100000, 0, to_find);
		if(addr <= 0x80000)
                {
                //        print "Found addr 0x%X" % addr
			MakeComm(addr, name);
                        AddCodeXref(addr, to_addr, XREF_USER);
			addr = NextHead(addr, 0x80000);
                 //       print "Continue search from addr 0x%X" % addr
                }
        }
}

static comment_all_gbr()
{
        auto i = 1;
	for(i = 1; i < 0x200; ++i)
        {
		auto addr = 0xFFFF8000 + i;
//		print "Processing addr 0x%X" % addr
		comment_text("@(h'%X,gbr)" % i, addr);
        }
}

static comment_all_gbr_tf80()
{
        auto i = 1;
	for(i = 0x168; i < 0x200; ++i)
        {
		auto addr = 0xFFFFA000 + i;
//		print "Processing addr 0x%X" % addr
		comment_text("@(h'%X,gbr)" % i, addr);
        }
}