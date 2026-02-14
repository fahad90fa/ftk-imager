CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
PREFIX ?= /usr/local

CORE_SRC = src/core/imager_core.c
CORE_BIN = build/forensic-imager-core

PYTHON ?= python3

.PHONY: all core install clean test

all: core

core:
	@mkdir -p build
	$(CC) $(CFLAGS) $(CORE_SRC) -o $(CORE_BIN) -lcrypto $(LDFLAGS)

install: core
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(CORE_BIN) $(DESTDIR)$(PREFIX)/bin/forensic-imager-core
	install -m 0755 scripts/forensic-imager $(DESTDIR)$(PREFIX)/bin/forensic-imager

clean:
	rm -rf build .pytest_cache

test:
	$(PYTHON) -m pytest -q
