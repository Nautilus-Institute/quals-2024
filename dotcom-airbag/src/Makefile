all: airbag dotcom_market bailout

bailout: bailout.c Makefile
	clang -o bailout bailout.c -O0

airbag: airbag.c Makefile build_elf.py
	 ./build_elf.py -o ./airbag airbag.c --cf '-z relro -z now -fstack-protector-all -Wno-executable-stack -lpthread' --strip 

dotcom_market: dotcom_market.c Makefile build_elf.py
	./build_elf.py -o ./dotcom_market ./dotcom_market.c --cf '-no-pie -g -z relro -z now -fno-stack-protector -lm'
