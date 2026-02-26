CLANG ?= clang
BPFTOOL ?= bpftool
LIBBPF_OBJ ?= /usr/lib/x86_64-linux-gnu/libbpf.a

TARGET := src/loader
BPF_OBJ := src/xdp_prog.o
BPF_SRC := src/xdp_prog.c
SKEL := src/xdp_prog.skel.h

# Flags for clang
BPF_CFLAGS ?= -O2 -g -target bpf -c -I/usr/include/x86_64-linux-gnu

all: $(TARGET) src/delta_agent_c src/decompress_agent

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -o $@ $<

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): src/loader.c $(SKEL)
	$(CC) -O2 -g -o $@ src/loader.c -lbpf -lelf -lz

src/delta_agent_c: src/delta_agent_c.c src/crypto_utils.h
	$(CC) -O2 -g -o $@ src/delta_agent_c.c -lz -lssl -lcrypto

src/decompress_agent: src/decompress_agent.c src/crypto_utils.h
	$(CC) -O2 -g -o $@ src/decompress_agent.c -lz -lssl -lcrypto

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) src/delta_agent_c src/decompress_agent
