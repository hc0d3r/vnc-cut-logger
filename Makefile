CFLAGS+=-Wall -Wextra -pie -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2
LDFLAGS+=-lcrypto -Wl,-z,relro,-z,now

vnc-cut-logger: vnc-cut-logger.c

clean:
	rm -f vnc-cut-logger

.PHONY: clean
