import logging, pathlib, datetime, io, re
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins import timeliner
from volatility3.plugins.windows import filescan
from volatility3.framework.renderers import format_hints, conversion

vollog = logging.getLogger(__name__)


class AnyDesk(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Parse the artifacts related to AnyDesk"""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                               architectures=["Intel32", "Intel64"]),
                requirements.PluginRequirement(name='filescan', plugin=filescan.FileScan, version=(0, 0, 0))]

    @classmethod
    def parse_trace_file(cls, file_raw, file_name):
        regexp = r'(info|error|debug|warning|auth) (.*) (lctrl|front|lsvc|ctrl|back|gsvc) .* - (.*)'
        for line in io.BytesIO(file_raw).readlines():
            decoded_string = line.decode('utf-8')
            result = re.search(regexp, decoded_string)
            if result:
                log_type = result.group(1)
                timestamp = datetime.datetime.strptime(result.group(2).rstrip(), "%Y-%m-%d %H:%M:%S.%f")
                context = result.group(3)
                message = result.group(4)
                yield file_name, log_type, timestamp, context, message

    def _generator(self, files):
        kernel = self.context.modules[self.config['kernel']]
        offsets = []
        for file_obj in files:
            """We need to identify the files linked to AnyDesk"""
            try:
                file_name = file_obj.FileName.String
                if "ad.trace" in file_name or "ad_svc.trace" in file_name:
                    """If found, try to dump the file (inspired from the "DumpFiles" plugin)"""
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
                        vollog.info(constants.LOGLEVEL_VVV,
                                    f"SharedCacheMap is unavailable for file {file_obj.vol.offset:#x}")
                    vollog.info(f"memory_objects : {memory_objects}")

                    for memory_object, layer in memory_objects:
                        bytes_read = 0
                        file_raw = b''
                        try:
                            for mem_offset, file_offset, datasize in memory_object.get_available_pages():
                                file_raw += layer.read(mem_offset, datasize, pad=True)
                                bytes_read += len(file_raw)
                                vollog.info(f"Read {bytes_read}")
                            if not bytes_read:
                                vollog.info(f"{file_name} is empty")
                            else:
                                """Parsing the trace files"""
                                for result in self.parse_trace_file(file_raw, file_name):
                                    yield 0, result
                        except exceptions.InvalidAddressException:
                            vollog.debug(f"Unable to dump file at {file_obj.vol.offset:#x}")
                            pass
            except exceptions.InvalidAddressException:
                continue

    def generate_timeline(self):
        kernel = self.context.modules[self.config['kernel']]
        for row in self._generator(
                filescan.FileScan.scan_files(self.context, kernel.layer_name, kernel.symbol_table_name)):
            _depth, row_data = row
            description = "{} : {} ".format(
                row_data[1], row_data[4])
            yield description, timeliner.TimeLinerType.CREATED, row_data[2]

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        return renderers.TreeGrid([
            ("Source", str),
            ("Type", str),
            ("Time", datetime.datetime),
            ("Context", str),
            ("Message", str)],
            self._generator(filescan.FileScan.scan_files(self.context, kernel.layer_name, kernel.symbol_table_name)))
