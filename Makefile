CLANG   ?= clang
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/' \
             | sed 's/aarch64/arm64/' \
             | sed 's/arm.*/arm/')

BPF_SRC  = src/kernel/monitor.bpf.c
BPF_HDR  = src/kernel/monitor.h
BPF_OBJ  = src/kernel/monitor.bpf.o
VMLINUX  = src/kernel/vmlinux.h

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean vmlinux run

all: $(BPF_OBJ)
	@echo "[OK] Bytecode eBPF compilado: $(BPF_OBJ)"

vmlinux: $(VMLINUX)

$(VMLINUX):
	@echo "  VMLINUX  $@"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX)
	@echo "  BPF      $@"
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I src/kernel \
		$(CLANG_BPF_SYS_INCLUDES) \
		-c $(BPF_SRC) -o $@

clean:
	rm -f $(BPF_OBJ)

run:
	@test -n "$(DOMAIN)" || (echo "Uso: make run DOMAIN=google.com [PORT=80]" && exit 1)
	sudo python3 main.py $(DOMAIN) $(PORT)
