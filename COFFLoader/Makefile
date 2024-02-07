CC := x86_64-w64-mingw32-gcc
LD := x86_64-w64-mingw32-ld
CFLAGS := -Wall -m64 -fno-builtin -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2
CCLDFLAGS := -Wl,-Tlinker.ld,--no-seh -DC2

S_SRCS := alignStack.asm
C_SRCS := APISolver.c COFFLoader.c BeaconFunctions.c
OBJS := $(patsubst %.asm,%.o,$(S_SRCS)) $(patsubst %.c,%.o,$(C_SRCS))

all: bin/COFFLoader.exe bin/COFFLoader.bin

bin/COFFLoader.exe: $(OBJS)
	mkdir -p $(@D)
	$(LD) -s $^ -o $@

bin/COFFLoader.bin: bin/COFFLoader.exe
	objcopy -j .text -O binary $< $@

%.o: %.asm
	nasm -f win64 $< -o $@

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@ $(CCLDFLAGS)

clean:
	rm -rf $(OBJS) \
		bin/COFFLoader.exe bin/COFFLoader.bin bin/
