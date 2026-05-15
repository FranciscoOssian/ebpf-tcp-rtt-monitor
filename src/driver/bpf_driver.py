import ctypes
import os
import sys

class BPFDriver:
    """Orquestra o carregamento e gerencimento de objetos eBPF via libbpf."""
    
    def __init__(self, obj_path="src/kernel/monitor.bpf.o"):
        self.obj_path = obj_path
        self.libbpf = self._load_libbpf()
        self.bpf_obj = None

    def _load_libbpf(self):
        """Busca e carrega a biblioteca libbpf compartilhada no sistema."""
        # Lista estendida de nomes comuns da libbpf em diferentes distros
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
        lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_program__attach.restype = ctypes.c_void_p
        lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
        lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.bpf_map__initial_value.restype = ctypes.c_void_p
        lib.bpf_map__initial_value.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        
        return lib

    def _setup_prototypes(self):
        self.libbpf.bpf_object__open_file.restype = ctypes.c_void_p
        self.libbpf.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        self.libbpf.bpf_object__load.restype = ctypes.c_int

    def load(self, target_ip_int):
        """Carrega o bytecode eBPF e injeta o IP alvo na seção .rodata."""
        if not os.path.exists(self.obj_path):
            raise FileNotFoundError(f"[-] Erro: {self.obj_path} não encontrado. Compile o código C primeiro.")

        self.bpf_obj = self.libbpf.bpf_object__open(self.obj_path.encode())
        
        # Injeção dinâmica de IP (Filtro)
        rodata_map = self.libbpf.bpf_object__find_map_by_name(self.bpf_obj, b".rodata")
        if rodata_map:
            size = ctypes.c_size_t()
            data_ptr = self.libbpf.bpf_map__initial_value(rodata_map, ctypes.byref(size))
            if data_ptr:
                ctypes.memmove(data_ptr, ctypes.byref(ctypes.c_uint32(target_ip_int)), 4)

        if self.libbpf.bpf_object__load(self.bpf_obj) != 0:
            raise RuntimeError("[-] Erro ao carregar o objeto eBPF no Kernel.")

    def attach_all(self):
        """Anexa as funções eBPF carregadas aos kprobes correspondentes."""
        progs = ["handle_tcp_connect", "handle_tcp_finish"]
        links = []
        for p_name in progs:
            prog = self.libbpf.bpf_object__find_program_by_name(self.bpf_obj, p_name.encode())
            if prog:
                link = self.libbpf.bpf_program__attach(prog)
                if link:
                    links.append(link)
        return links
