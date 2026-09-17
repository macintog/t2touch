# SPDX-License-Identifier: GPL-2.0-only
obj-m += t2_sep_transport.o

KDIR ?= /lib/modules/$(shell uname -r)/build

HARDEN := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wformat -Wformat-security
LDHARDEN := -pie -Wl,-z,relro,-z,now,-z,noexecstack

.PHONY: all module recovery-tools clean

all: module t2-aks-tool t2-pam-fingerprint-prompt pam_t2touch_action_prompt.so t2-recovery-usb-observer

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

t2-aks-tool: t2-aks-tool.c t2_sep_transport_uapi.h
	$(CC) -O2 -Wall -Wextra -Werror $(HARDEN) $(LDHARDEN) -o t2-aks-tool t2-aks-tool.c

t2-pam-fingerprint-prompt: t2-pam-fingerprint-prompt.c
	$(CC) -O2 -Wall -Wextra -Werror $(HARDEN) $(LDHARDEN) -o t2-pam-fingerprint-prompt t2-pam-fingerprint-prompt.c

pam_t2touch_action_prompt.so: pam_t2touch_action_prompt.c
	$(CC) -O2 -Wall -Wextra -Werror -fPIC -shared -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Wl,-z,relro,-z,now,-z,noexecstack -o $@ $< -lpam

t2-recovery-usb-observer: t2-recovery-usb-observer.c
	$(CC) -O2 -Wall -Wextra -Werror $(HARDEN) $(LDHARDEN) -o t2-recovery-usb-observer t2-recovery-usb-observer.c

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) t2-aks-tool t2-pam-fingerprint-prompt pam_t2touch_action_prompt.so t2-recovery-usb-observer
