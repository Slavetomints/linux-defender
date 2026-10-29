obj-m += nic_fw.o

KVER ?= $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
