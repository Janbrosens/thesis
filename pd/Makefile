ENCL_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIC -fpie \
	       -fno-stack-protector -mrdrnd $(INCLUDES)
ENCL_OPT    := -Os

.PHONY : all clean
all: encl.elf

encl.elf: test_encl.lds test_encl.c test_encl_bootstrap.S
	$(CC) $(ENCL_OPT) $(ENCL_CFLAGS) -T $^ -o $@ -Wl,--build-id=none

clean:
	rm -Rf *.o *.elf
