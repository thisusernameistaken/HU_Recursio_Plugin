from binaryninja import BinaryView, StructureBuilder, BinaryReader, StructureType
from binaryninja import Architecture, Symbol, Type
from binaryninja.enums import SectionSemantics,SegmentFlag, SymbolType

class RecursoLoader(BinaryView):

    name = "recurso"
    long_name = "Recurso Program"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.raw = data
        self.br = data.reader()
        self.function_list = []

    @classmethod
    def is_valid_for_data(cls,data):
        if data.file.original_filename.endswith(".recc"):
            return True
        return False

    def init(self):
        self.platform = Architecture['recurso'].standalone_platform
        self.arch = Architecture['recurso']

        header_size = self.br.read32le(0)+4
        self.add_auto_segment(0,header_size,0,header_size,SegmentFlag.SegmentReadable)
        self.add_auto_section("header",0,header_size,SectionSemantics.ReadOnlyDataSectionSemantics)
        
        self.add_auto_segment(0x100000,self.parent_view.length,header_size,self.parent_view.length,SegmentFlag.SegmentReadable)
        self.add_auto_section("code",0x100000,self.parent_view.length,SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.entry_addr = 0x100000

        with StructureBuilder.builder(self,"recursio_header_t") as struct:
            struct.packed = True
            struct.append(Type.int(4,False),"header_size")
            self._load_header(header_size,struct)
        
        header_struct = Type.named_type_from_registered_type(self,"recursio_header_t")
        self.define_data_var(0,header_struct)
        
        self.add_entry_point(self.entry_addr)
        self.add_function(self.entry_addr)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,self.entry_addr,"entry"))

        return True

    def _load_header(self,header_size,struct):
        sym_count = 0
        while self.br.offset < header_size:
            start_byte = self.br.read(1)
            with StructureBuilder.builder(self,f"recursio_func_symbol_{sym_count}") as sym_struct:
                sym_struct.packed = True
                if ord(start_byte) == 0x11:
                    s = 0 
                    sym_count += 1
                    sym_name = b""
                    curr = self.br.read(1)
                    sym_struct.append(Type.char(),f"func_sym_start_{sym_count}")
                    while ord(curr) != 0x12:
                        sym_name += curr
                        curr = self.br.read(1)
                        s += 1
                    func_args = self.br.read32be(self.br.offset)
                    func_off = self.br.read32be(self.br.offset)
                    sym_struct.append(Type.array(Type.char(),s),f"func_sym_name_{sym_count}")
                    sym_struct.append(Type.char(),f"func_sym_end_{sym_count}")
                    sym_struct.append(Type.int(4,False),f"func_args_{sym_count}")
                    sym_struct.append(Type.int(4,False),f"func_offset_{sym_count}")
                    
                    self.add_function(self.entry_addr+func_off)
                    self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,self.entry_addr+func_off,sym_name))
                    
                    sym_struct_t = Type.structure_type(sym_struct)
                    struct.append(sym_struct_t)
                    
                    # TODO: add arguments

                    self.function_list.append(sym_name)
                


    

