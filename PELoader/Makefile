CC := x86_64-w64-mingw32-gcc
LD := x86_64-w64-mingw32-ld
CFLAGS := -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2
CCLDFLAGS := -Wl,-Tlinker.ld,--no-seh -DC2

S_SRCS := alignStack.asm
C_SRCS := APISolver.c PELoader.c
OBJS := $(patsubst %.asm,%.o,$(S_SRCS)) $(patsubst %.c,%.o,$(C_SRCS))

all: bin/PELoader.exe bin/PELoader.bin

bin/PELoader.exe: $(OBJS)
	mkdir -p $(@D)
	$(LD) -s $^ -o $@

bin/PELoader.bin: bin/PELoader.exe
	objcopy -j .text -O binary $< $@

%.o: %.asm
	nasm -f win64 $< -o $@

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@ $(CCLDFLAGS)

clean:
	rm -rf $(OBJS) \
		bin/PELoader.exe bin/PELoader.bin bin/
