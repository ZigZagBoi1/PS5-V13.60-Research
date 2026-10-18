PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

ELF := ps5-kernel-dumper.elf
FULL_ELF := ps5-full-kernel-dumper.elf
CFLAGS := -Wall -Wextra -Werror -O2
PS5_HOST ?=
PS5_PORT ?= 9021

all: $(ELF) $(FULL_ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $<

$(FULL_ELF): full_dump.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(ELF) $(FULL_ELF)

deploy: $(ELF)
	@test -n "$(PS5_HOST)" || (echo "Set PS5_HOST to the console IP"; exit 1)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

deploy-full: $(FULL_ELF)
	@test -n "$(PS5_HOST)" || (echo "Set PS5_HOST to the console IP"; exit 1)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

.PHONY: all clean deploy deploy-full
