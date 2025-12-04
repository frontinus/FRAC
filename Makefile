CLANG ?= clang
BPFTOOL ?= bpftool
LIBBPF_OBJ ?= /usr/lib/x86_64-linux-gnu/libbpf.a

TARGET := loader
BPF_OBJ := xdp_prog.o
BPF_SRC := xdp_prog.c
SKEL := xdp_prog.skel.h

# Flags for clang
BPF_CFLAGS ?= -O2 -g -target bpf -c -I/usr/include/x86_64-linux-gnu

all: $(TARGET)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -o $@ $<

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): loader.c $(SKEL)
	$(CC) -O2 -g -o $@ loader.c -lbpf -lelf -lz

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL)
