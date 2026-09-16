# SPDX-License-Identifier: GPL-2.0-only
obj-m += t2_sep_transport.o

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all module recovery-tools clean

all: module t2-aks-tool t2-pam-fingerprint-prompt pam_t2touch_action_prompt.so

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

t2-aks-tool: t2-aks-tool.c t2_sep_transport_uapi.h
	$(CC) -O2 -Wall -Wextra -Werror -o t2-aks-tool t2-aks-tool.c

t2-pam-fingerprint-prompt: t2-pam-fingerprint-prompt.c
	$(CC) -O2 -Wall -Wextra -Werror -o t2-pam-fingerprint-prompt t2-pam-fingerprint-prompt.c

pam_t2touch_action_prompt.so: pam_t2touch_action_prompt.c
	$(CC) -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,relro,-z,now -o $@ $< -lpam

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) t2-aks-tool t2-pam-fingerprint-prompt pam_t2touch_action_prompt.so
