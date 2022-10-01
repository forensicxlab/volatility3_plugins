# References :
# https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/%5bMS-XCA%5d.pdf
# https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
# https://github.com/volatilityfoundation/volatility3/
# https://github.com/EricZimmerman/Prefetch/tree/master/Prefetch
import logging, pathlib, datetime, io, numpy
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import filescan
from volatility3.framework.renderers import format_hints, conversion

vollog = logging.getLogger(__name__)


def encoded_bit_length(data, symbol):
    if (symbol % 2) == 0:
        return int(data[symbol // 2] & 0x0f)
    else:
        return int(data[symbol // 2] >> 4)


def read_16_bits(input, current_position):
    stream = io.BytesIO(input)
    stream.seek(current_position)
    byte_value = bytearray(stream.read(2))
    val = numpy.uint16(0)
    j = 0
    for i in byte_value:
        val = val | (numpy.uint16(i) << numpy.uint(j * 8))
        j = j + 1
    return val


def read_byte(input, current_position):
    stream = io.BytesIO(input)
    stream.seek(current_position)
    return int.from_bytes(stream.read(1), "little")


def decompress_prefetch(data, out):
    """
    Description : Decompress the prefetch using LZ77+Huffman Decompression Algorithm
    Params :
        @data : The compressed prefetch data extracted from memory
        @result : The uncompressed prefetch file ready to be forensically analysed
    Possible errors :
        Invalid compressed data.
    """
    if len(data) < 256:
        vollog.info("Error : The prefetch must use a 256-byte Huffman table. -> Invalid data")

    # First, we construct our table
    decoding_table = [0] * (2 ** 15)
    current_table_entry = 0
    encoded_data = data[0:256]
    for bit_length in range(1, 15):
        for symbol in range(0, 511):
            if encoded_bit_length(encoded_data,
                                  symbol) == bit_length:  # If the encoded bit length of symbol equals bit_length
                entry_count = (1 << (15 - bit_length))
                for i in range(0, entry_count):
                    if current_table_entry >= 2 ** 15:  # Huffman table length
                        vollog.info("The compressed data is not valid.")
                        return None
                    decoding_table[current_table_entry] = numpy.uint16(symbol)
                    current_table_entry += 1
    if current_table_entry != 2 ** 15:
        vollog.info("The compressed data is not valid.")
        exit(1)

    # Then, it's time to decompress the data
    """
    The compression stream is designed to be read in (mostly) 16-bit chunks, with a 32-bit register
    maintaining at least the next 16 bits of input. This strategy allows the code to seamlessly handle the
    bytes for long match lengths, which would otherwise be awkward.
    """
    input_buffer = data
    current_position = 256  # start at the end of the Huffman table
    if current_position > len(input_buffer):
        vollog.info("Incomplete Prefetch")
        return out
    next_bits = read_16_bits(input_buffer, current_position)
    current_position += 2
    next_bits = numpy.uint32(next_bits) << numpy.int64(16)
    if current_position > len(input_buffer):
        vollog.info("Incomplete Prefetch")
        return out
    next_bits = next_bits | numpy.uint32(read_16_bits(input_buffer, current_position))

    current_position += 2
    extra_bit_count = 16
    # Loop until a block terminating condition
    while True:
        next_15_bits = numpy.uint32(next_bits) >> numpy.uint32((32 - 15))
        huffman_symbol = decoding_table[next_15_bits]
        huffman_symbol_bit_length = encoded_bit_length(encoded_data, huffman_symbol)
        next_bits = numpy.int32(next_bits << huffman_symbol_bit_length)
        extra_bit_count -= huffman_symbol_bit_length
        if extra_bit_count < 0:
            if current_position > len(input_buffer):
                vollog.info("Incomplete Prefetch")
                return out
            next_bits = next_bits | (numpy.uint32(read_16_bits(input_buffer, current_position)) << (-extra_bit_count))
            current_position += 2
            extra_bit_count += 16
        if huffman_symbol < 256:
            out.append(huffman_symbol)
        elif huffman_symbol == 256 and (len(input_buffer) - current_position) == 0:
            vollog.info("Decompression is complete")
            return out
        else:
            huffman_symbol = huffman_symbol - 256
            match_length = huffman_symbol % 16
            match_offset_bit_length = huffman_symbol // 16
            if match_length == 15:
                if current_position > len(input_buffer):
                    vollog.info("Incomplete Prefetch")
                    return out
                match_length = numpy.uint16(read_byte(input_buffer, current_position))
                current_position += 1
                if match_length == 255:
                    if current_position > len(input_buffer):
                        vollog.info("Incomplete Prefetch")
                        return out
                    match_length = read_16_bits(input_buffer, current_position)
                    current_position += 2
                    if match_length < 15:
                        vollog.info("The compressed data is invalid.")
                        return None
                    match_length -= 15
                match_length += 15
            match_length += 3
            match_offset = next_bits >> (32 - match_offset_bit_length)
            match_offset += (1 << match_offset_bit_length)
            next_bits = next_bits << match_offset_bit_length
            extra_bit_count -= match_offset_bit_length
            if extra_bit_count < 0:
                if current_position > len(input_buffer):
                    vollog.info("Incomplete Prefetch")
                    return out
                next_bits = next_bits | (
                        numpy.uint32(read_16_bits(input_buffer, current_position)) << (-extra_bit_count))
                current_position += 2
                extra_bit_count += 16
            for i in range(0, int(match_length)):
                to_write = out[len(out) - int(match_offset)]
                out.append(to_write)


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
            prefetch_file = decompress_prefetch(bytearray(compressed_bytes), bytearray())
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
                            for mem_offset, file_offset, datasize in memory_object.get_available_pages():
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
