import ctypes
import os


class FourTuple(ctypes.Structure):
    """Estrutura C da 4-tuple (12 bytes, sem padding).
    Deve corresponder exatamente ao layout de struct four_tuple no BPF."""
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
    ]


class BPFDriver:
    """Orquestra o carregamento e gerencimento de objetos eBPF via libbpf."""
    
    def __init__(self, obj_path="src/kernel/monitor.bpf.o"):
        self.obj_path = obj_path
        self.libbpf = self._load_libbpf()
        self.bpf_obj = None
        self._links = []

    def _load_libbpf(self):
        """Busca e carrega a biblioteca libbpf compartilhada no sistema."""
        libs = ["libbpf.so", "libbpf.so.1", "libbpf.so.0", "libbpf.so.1.2.0"]

        lib = None
        for l in libs:
            try:
                lib = ctypes.CDLL(l)
                break
            except OSError:
                continue

        if not lib:
            raise RuntimeError("[-] Erro: libbpf não encontrada. Instale libbpf-dev (Ubuntu) ou libbpf-devel (Fedora).")
            
        # Define os protótipos das funções C para evitar erros de tipos
        lib.bpf_object__open.restype = ctypes.c_void_p
        lib.bpf_object__open.argtypes = [ctypes.c_char_p]
        lib.bpf_object__load.restype = ctypes.c_int
        lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        lib.bpf_object__close.restype = None
        lib.bpf_object__close.argtypes = [ctypes.c_void_p]

        # Operações de programa
        lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_program__attach.restype = ctypes.c_void_p
        lib.bpf_program__attach.argtypes = [ctypes.c_void_p]

        # Operações de mapa (metadados)
        lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_map__fd.restype = ctypes.c_int
        lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        lib.bpf_map__initial_value.restype = ctypes.c_void_p
        lib.bpf_map__initial_value.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]

        # Operações de mapa (acesso a dados via bpf syscall)
        lib.bpf_map_lookup_elem.restype = ctypes.c_int
        lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        lib.bpf_map_get_next_key.restype = ctypes.c_int
        lib.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

        return lib

    def load(self, target_ip_int=0):
        """Carrega o bytecode eBPF e injeta o IP alvo na seção .rodata."""
        if not os.path.exists(self.obj_path):
            raise FileNotFoundError(f"[-] Erro: {self.obj_path} não encontrado. Compile o código C primeiro.")

        self.bpf_obj = self.libbpf.bpf_object__open(self.obj_path.encode())
        if not self.bpf_obj:
            raise RuntimeError("Falha ao abrir objeto eBPF.")

        # Injeção do IP alvo na variável target_daddr (.rodata)
        if target_ip_int:
            rodata = self.libbpf.bpf_object__find_map_by_name(self.bpf_obj, b".rodata")
            if rodata:
                size = ctypes.c_size_t()
                data_ptr = self.libbpf.bpf_map__initial_value(rodata, ctypes.byref(size))
                if data_ptr:
                    ctypes.memmove(data_ptr, ctypes.byref(ctypes.c_uint32(target_ip_int)), 4)

        if self.libbpf.bpf_object__load(self.bpf_obj) != 0:
            raise RuntimeError("[-] Erro ao carregar o objeto eBPF no Kernel.")

    def attach(self):
        """Anexa o programa eBPF ao tracepoint sock/inet_sock_set_state."""
        prog = self.libbpf.bpf_object__find_program_by_name(
            self.bpf_obj, b"handle_set_state"
        )
        if not prog:
            raise RuntimeError("Programa 'handle_set_state' não encontrado no objeto BPF.")

        link = self.libbpf.bpf_program__attach(prog)
        if not link:
            raise RuntimeError("Falha ao anexar programa ao tracepoint.")
        self._links.append(link)

    def read_rtt_results(self):
        """Lê os resultados de RTT diretamente do mapa BPF rtt_results.

        Retorna uma lista de dicts com saddr, daddr, sport, dport e rtt_us.
        """
        rtt_map = self.libbpf.bpf_object__find_map_by_name(self.bpf_obj, b"rtt_results")
        if not rtt_map:
            return []

        fd = self.libbpf.bpf_map__fd(rtt_map)
        if fd < 0:
            return []

        results = []
        key = FourTuple()
        next_key = FourTuple()
        value = ctypes.c_uint64()

        # Itera todas as entradas do mapa hash
        err = self.libbpf.bpf_map_get_next_key(fd, None, ctypes.byref(next_key))
        while err == 0:
            ctypes.memmove(ctypes.byref(key), ctypes.byref(next_key), ctypes.sizeof(FourTuple))
            if self.libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(value)) == 0:
                results.append({
                    "saddr": key.saddr,
                    "daddr": key.daddr,
                    "sport": key.sport,
                    "dport": key.dport,
                    "rtt_us": value.value,
                })
            err = self.libbpf.bpf_map_get_next_key(fd, ctypes.byref(key), ctypes.byref(next_key))

        return results

    def close(self):
        """Libera recursos do objeto BPF."""
        if self.bpf_obj:
            self.libbpf.bpf_object__close(self.bpf_obj)
            self.bpf_obj = None
