all: dirs lceditor

dirs:
	@mkdir -p out

lceditor:dirs
	gcc $@.c bin.c -o out/$@

debug:dirs
	gcc lceditor.c bin.c -o out/lceditor -g

tst:dirs
	gcc $@.c -o out/$@ -arch x86_64 -arch i386

clean:
	rm -rf out

libtst:dirs
	gcc libtst.c -o out/libtstlib.dylib -dynamiclib -arch x86_64 -arch i386
