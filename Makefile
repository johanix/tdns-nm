all:
	$(MAKE) -C ./cmd/tdns-kdc
	$(MAKE) -C ./cmd/tdns-krs
	$(MAKE) -C ./cmd/kdc-cli
	$(MAKE) -C ./cmd/krs-cli

clean:
	$(MAKE) -C ./cmd/tdns-kdc clean
	$(MAKE) -C ./cmd/tdns-krs clean
	$(MAKE) -C ./cmd/kdc-cli clean
	$(MAKE) -C ./cmd/krs-cli clean

install:
	$(MAKE) -C ./cmd/tdns-kdc install
	$(MAKE) -C ./cmd/tdns-krs install
	$(MAKE) -C ./cmd/kdc-cli install
	$(MAKE) -C ./cmd/krs-cli install

# Run a KDC and a KRS on 127.0.0.1 and exercise the four programs
smoke: all
	/bin/bash tests/smoke.sh

include utils/Makefile.common

