# References :
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/%5bMS-XCA%5d.pdf
# https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
# https://github.com/volatilityfoundation/volatility3/
# https://github.com/EricZimmerman/Prefetch/tree/master/Prefetch
import logging, pathlib, datetime, io, struct
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import filescan
from volatility3.framework.renderers import format_hints, conversion

vollog = logging.getLogger(__name__)
from typing import Tuple, List, Union

class BitStream:
    def __init__(self, source: bytes, in_pos: int):
        self.source = source
        self.index = in_pos + 4
        # read UInt16 little endian
        mask = struct.unpack_from('<H', source, in_pos)[0] << 16
        mask += struct.unpack_from('<H', source, in_pos + 2)[0]
        self.mask = mask
        self.bits = 32

    def lookup(self, n: int) -> int:
        if n == 0:
            return 0
        return self.mask >> (32 - n)
        
    def skip(self, n: int) -> Union[None, Exception]:
        self.mask = ((self.mask << n) & 0xFFFFFFFF)
        self.bits -= n
        if self.bits < 16:
            if self.index + 2 > len(self.source):
                return Exception("EOF Error")
            # read UInt16 little endian
            self.mask += ((struct.unpack_from('<H', self.source, self.index)[0]) << (16 - self.bits)) & 0xFFFFFFFF 
            self.index += 2
            self.bits += 16

        return None

    def __str__(self):
        return f"{self.id}: symbol {self.symbol} length {self.length}"
class PREFIX_CODE_NODE:
    def __init__(self):
        self.id = 0
        self.symbol = 0
        self.leaf = False
        self.child = [None, None]

    def __str__(self):
        return f"Node {self.id}: symbol {self.symbol} leaf {self.leaf}"

class PREFIX_CODE_SYMBOL:
    def __init__(self):
        self.id = 0
        self.symbol = 0
        self.length = 0

    def __str__(self):
        return f"Symbol {self.id}: symbol {self.symbol} length {self.length}"


def prefix_code_tree_add_leaf(treeNodes: List[PREFIX_CODE_NODE], leafIndex: int, mask: int, bits: int) -> int:
    node = treeNodes[0]
    i = leafIndex + 1
    childIndex = None

    while bits > 1:
        bits -= 1
        childIndex = (mask >> bits) & 1
        if node.child[childIndex] == None:
            node.child[childIndex] = treeNodes[i]
            treeNodes[i].leaf = False
            i += 1
        node = node.child[childIndex]

    node.child[mask&1] = treeNodes[leafIndex]

    return i

def prefix_code_tree_rebuild(input: bytes) -> PREFIX_CODE_NODE:
    treeNodes = [PREFIX_CODE_NODE() for _ in range(1024)]
    symbolInfo = [PREFIX_CODE_SYMBOL() for _ in range(512)]

    for i in range(256):
        value = input[i]

        symbolInfo[2*i].id = 2 * i
        symbolInfo[2*i].symbol = 2 * i
        symbolInfo[2*i].length = value & 0xf

        value >>= 4

        symbolInfo[2*i+1].id = 2*i + 1
        symbolInfo[2*i+1].symbol = 2*i + 1
        symbolInfo[2*i+1].length = value & 0xf

    symbolInfo = sorted(symbolInfo, key=lambda x: (x.length, x.symbol))

    i = 0
    while i < 512 and symbolInfo[i].length == 0:
        i += 1

    mask = 0
    bits = 1

    root = treeNodes[0]
    root.leaf = False

    j = 1
    while i < 512:
        treeNodes[j].id = j
        treeNodes[j].symbol = symbolInfo[i].symbol
        treeNodes[j].leaf = True
        mask = mask << (symbolInfo[i].length - bits)
        bits = symbolInfo[i].length
        j = prefix_code_tree_add_leaf(treeNodes, j, mask, bits)
        mask += 1
        i += 1

    return root

def prefix_code_tree_decode_symbol(bstr: BitStream, root: PREFIX_CODE_NODE) -> Tuple[int, Union[None, Exception]]:
    node = root
    i = 0
    while True:
        bit = bstr.lookup(1)
        err = bstr.skip(1)
        if err is not None:
            return 0, err

        node = node.child[bit]
        if node == None:
            return 0, Exception("Corruption detected")

        if node.leaf:
            break
    return node.symbol, None

def lz77_huffman_decompress_chunck(in_idx: int, 
                                   input: bytes, 
                                   out_idx: int, 
                                   output: bytearray, 
                                   chunk_size: int) -> Tuple[int, int, Union[None, Exception]]:
    
    # Ensure there are at least 256 bytes available to read
    if in_idx + 256 > len(input):
        return 0, 0, Exception("EOF Error")

    root = prefix_code_tree_rebuild(input[in_idx:])
    #print_tree(root)
    bstr = BitStream(input, in_idx+256)

    i = out_idx

    while i < out_idx + chunk_size:
        symbol, err = prefix_code_tree_decode_symbol(bstr, root)
        
        if err is not None:
            return int(bstr.index), i, err
        
        if symbol < 256:
            output[i] = symbol
            i += 1
        else:
            symbol -= 256
            length = symbol & 15
            symbol >>= 4

            offset = 0
            if symbol != 0:
                offset = int(bstr.lookup(symbol))

            offset |= 1 << symbol
            offset = -offset

            if length == 15:
                length = bstr.source[bstr.index] + 15
                bstr.index += 1
                
                if length == 270:
                    length = struct.unpack_from('<H', bstr.source, bstr.index)[0]
                    bstr.index += 2

            err = bstr.skip(symbol)
            if err is not None:
                return int(bstr.index), i, err
            
            length += 3
            while length > 0:
                if i + offset < 0:
                    print(i + offset)
                    return int(bstr.index), i, Exception("Decompression Error")
                
                output[i] = output[i + offset]
                i += 1
                length -= 1
                if length==0:
                    break
    return int(bstr.index), i, None


def lz77_huffman_decompress(input: bytes, output_size: int) -> Tuple[bytes, Union[None, Exception]]:
    output = bytearray(output_size)
    err = None

    # Index into the input buffer.
    in_idx = 0

    # Index into the output buffer.
    out_idx = 0

    while True:
        # How much data belongs in the current chunk. Chunks
        # are split into maximum 65536 bytes.
        chunk_size = output_size - out_idx
        if chunk_size > 65536:
            chunk_size = 65536

        in_idx, out_idx, err = lz77_huffman_decompress_chunck(
            in_idx, input, out_idx, output, chunk_size)
        if err is not None:
            return output, err
        if out_idx >= len(output) or in_idx >= len(input):
            break
    return output, None

class Prefetch(interfaces.plugins.PluginInterface):
    """Get and parse the prefetch files"""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                               architectures=["Intel32", "Intel64"]),
                requirements.PluginRequirement(name='filescan', plugin=filescan.FileScan, version=(0, 0, 0)), ]

    @classmethod
    def version_17(cls, prefetch_file):
        """Extract pf information for Version 17"""
        stream = io.BytesIO(prefetch_file)

        stream.seek(0x000C)
        file_size = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0010)
        executable_raw = stream.read(60).decode('utf-16')
        executable_name = executable_raw.split('\u0000')[0]

        stream.seek(0x004C)
        prefetch_hash = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0078)
        last_execution_filetime = int.from_bytes(stream.read(8), "little")
        last_execution_filetime_human = conversion.wintime_to_datetime(last_execution_filetime)

        stream.seek(0x0090)
        execution_counter = int.from_bytes(stream.read(4), "little")

        yield (
            executable_name,
            file_size,
            format_hints.Hex(prefetch_hash),
            last_execution_filetime_human,
            execution_counter
        )

    @classmethod
    def version_23(cls, prefetch_file):
        """Extract pf information for Version 23"""
        stream = io.BytesIO(prefetch_file)

        stream.seek(0x000C)
        file_size = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0010)
        executable_raw = stream.read(60).decode('utf-16')
        executable_name = executable_raw.split('\u0000')[0]

        stream.seek(0x004C)
        prefetch_hash = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0080)
        last_execution_filetime = int.from_bytes(stream.read(8), "little")
        last_execution_filetime_human = conversion.wintime_to_datetime(last_execution_filetime)

        stream.seek(0x0098)
        execution_counter = int.from_bytes(stream.read(4), "little")

        yield (
            executable_name,
            file_size,
            format_hints.Hex(prefetch_hash),
            last_execution_filetime_human,
            execution_counter
        )

    @classmethod
    def version_26(cls, prefetch_file):
        """Extract pf information for Version 26"""
        stream = io.BytesIO(prefetch_file)

        stream.seek(0x000C)
        file_size = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0010)
        executable_raw = stream.read(60).decode('utf-16')
        executable_name = executable_raw.split('\u0000')[0]

        stream.seek(0x004C)
        prefetch_hash = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0080)
        last_execution_filetime = int.from_bytes(stream.read(8), "little")
        last_execution_filetime_human = conversion.wintime_to_datetime(last_execution_filetime)

        stream.seek(0x00D0)
        execution_counter = int.from_bytes(stream.read(4), "little")

        yield (
            executable_name,
            file_size,
            format_hints.Hex(prefetch_hash),
            last_execution_filetime_human,
            execution_counter
        )

    @classmethod
    def version_30(cls, prefetch_file):
        """Extract pf information for Version 30"""
        stream = io.BytesIO(prefetch_file)

        stream.seek(0x000C)
        file_size = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0010)
        executable_raw = stream.read(60).decode('utf-16')
        executable_name = executable_raw.split('\u0000')[0]

        stream.seek(0x004C)
        prefetch_hash = int.from_bytes(stream.read(4), "little")

        stream.seek(0x0080)
        # The first FILETIME is the most recent run time
        last_execution_filetime = int.from_bytes(stream.read(8), "little")
        last_execution_filetime_human = conversion.wintime_to_datetime(last_execution_filetime)

        stream.seek(0x00C8)  # Variant 1
        execution_counter = int.from_bytes(stream.read(4), "little")
        if execution_counter == 0:
            stream.seek(0x00D0)  # Variant 2
            execution_counter = int.from_bytes(stream.read(4), "little")

        yield (
            executable_name,
            file_size,
            format_hints.Hex(prefetch_hash),
            last_execution_filetime_human,
            execution_counter
        )

    @classmethod
    def parse_prefetch(cls, prefetch_file):
        WinXpOrWin2K3 = 17
        VistaOrWin7 = 23
        Win8xOrWin2012x = 26
        Win10OrWin11 = 30
        stream = io.BytesIO(prefetch_file)
        # First, we need to know if the prefetch is compressed (Win10/11)
        signature = prefetch_file[:3].decode()
        if signature == "MAM":
            vollog.info("Windows 1X prefetch file detected.")
            # The size of decompressed data is at offset 4
            stream.seek(0x0004)
            decompressed_size = int.from_bytes(stream.read(4), "little")
            vollog.info(f"decompressed size : {decompressed_size}")
            stream.seek(0x0008)
            compressed_bytes = stream.read()
            prefetch_file = lz77_huffman_decompress(bytearray(compressed_bytes), decompressed_size)[0]
        try:
            file_version = int.from_bytes(prefetch_file[:4], "little")
            signature = prefetch_file[4:8].decode()
            vollog.info(f'File version : {file_version}')
            vollog.info(f"Signature : {signature}")
        except:
            # We can not even read the header
            pass

        if signature != "SCCA":
            vollog.info("Wrong signature, should be SCCA")
            return
        if file_version == WinXpOrWin2K3:
            for result in cls.version_17(prefetch_file):
                yield result
        elif file_version == VistaOrWin7:
            for result in cls.version_23(prefetch_file):
                yield result
        elif file_version == Win8xOrWin2012x:
            for result in cls.version_26(prefetch_file):
                yield result
        elif file_version == Win10OrWin11:
            for result in cls.version_30(prefetch_file):
                yield result

    def _generator(self, files):
        kernel = self.context.modules[self.config['kernel']]
        offsets = []
        for file_obj in files:
            """Get the prefetch recovered files from the “filescan” plugin; """
            try:
                file_name = file_obj.FileName.String
                file_extension = pathlib.Path(file_name).suffix
                if file_extension == ".pf":
                    """If found, try to dump the prefetch file (inspired from the "DumpFiles" plugin)"""
                    memory_objects = []
                    memory_layer_name = self.context.layers[kernel.layer_name].config['memory_layer']
                    memory_layer = self.context.layers[memory_layer_name]
                    primary_layer = self.context.layers[kernel.layer_name]
                    for member_name in ["DataSectionObject", "ImageSectionObject"]:
                        try:
                            section_obj = getattr(file_obj.SectionObjectPointer, member_name)
                            control_area = section_obj.dereference().cast("_CONTROL_AREA")
                            if control_area.is_valid():
                                vollog.info(f"Found : {file_obj.FileName.String}")
                                memory_objects.append((control_area, memory_layer))
                        except exceptions.InvalidAddressException:
                            vollog.log(constants.LOGLEVEL_VVV,
                                       f"{member_name} is unavailable for file {file_obj.vol.offset:#x}")
                    try:
                        scm_pointer = file_obj.SectionObjectPointer.SharedCacheMap
                        shared_cache_map = scm_pointer.dereference().cast("_SHARED_CACHE_MAP")
                        if shared_cache_map.is_valid():
                            memory_objects.append((shared_cache_map, primary_layer))
                    except exceptions.InvalidAddressException:
                        vollog.log(constants.LOGLEVEL_VVV,
                                   f"SharedCacheMap is unavailable for file {file_obj.vol.offset:#x}")
                    vollog.info(f"memory_objects : {memory_objects}")

                    """Now, read and parse our PF to retrieve our artifacts"""
                    for memory_object, layer in memory_objects:
                        bytes_read = 0
                        prefetch_raw = b''
                        try:
                            for mem_offset, _, datasize in memory_object.get_available_pages():
                                prefetch_raw += layer.read(mem_offset, datasize, pad=True)
                                bytes_read += len(prefetch_raw)
                                vollog.info(f"Read {bytes_read}")
                            if not bytes_read:
                                vollog.info(f"Prefetch is empty")
                            else:
                                """Prefetch parsing"""
                                for result in self.parse_prefetch(prefetch_raw):
                                    yield 0, result

                        except exceptions.InvalidAddressException:
                            vollog.debug(f"Unable to dump file at {file_obj.vol.offset:#x}")
                            pass
            except exceptions.InvalidAddressException:
                continue

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        return renderers.TreeGrid([
            ("ExecutableName", str),
            ("FileSize", int),
            ("PrefetchHash", format_hints.Hex),
            ("LastExecution", datetime.datetime), ("ExecutionCounter", int)],
            self._generator(filescan.FileScan.scan_files(self.context, kernel.layer_name, kernel.symbol_table_name)))
