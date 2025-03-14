COMPILER = gcc
FILESYSTEM_FILES = enfuse.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) -o enfuse `pkg-config fuse --cflags --libs`
	echo 'To Mount: ./enfuse -f [mount point]'

clean:
	rm -f enfuse
