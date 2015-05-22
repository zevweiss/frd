default: frd.ko

KVERSION := $(shell uname -r)

KSRC = /lib/modules/$(KVERSION)/build

obj-m += frd.o

frd.ko:
	$(MAKE) -C $(KSRC) M=$(PWD) modules

clean:
	$(MAKE) -C $(KSRC) M=$(PWD) clean
