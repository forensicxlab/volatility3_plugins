import contextlib
import logging
from typing import List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class KeePass(interfaces.plugins.PluginInterface):
    """Print the keepass potential password matches"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid",
                description="Keepass process ID",
                optional=False,
            ),
        ]
    
    def format_match(self, matches):
        # Buid a string of the current password found
        final_string = ''
        for position in sorted(matches.keys()):
            size = len(matches[position]) - 1
            if size > 1:
                final_string += "{"
                for i in range(0, size - 1):
                    final_string += matches[position][i] + ","
                final_string += matches[position][size] + "}"
            else:
                final_string += matches[position][0]
        return final_string


    def _generator(self, procs):
        for proc in procs:
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        pid, excp.invalid_address, excp.layer_name
                    )
                )
                continue

            file_handle = contextlib.ExitStack()
            matches = {}
            with file_handle as file_data:
                file_offset = 0
                for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors=True):
                    offset = mapval[0]
                    size = mapval[1]
                    try:
                        data = proc_layer.read(offset, size, pad=True)
                        position = 0
                        i = 0
                        while i < len(data)-1:
                            if (data[i] == 0xCF) and (data[i + 1] == 0x25):
                                position += 1
                                i += 1
                            elif position > 0:
                                if (data[i] >= 0x20) and (data[i] <= 0x7E) and (data[i + 1] == 0x00):
                                    if not position in matches:
                                        matches[position] = []
                                    match = bytes([data[i], data[i + 1]]).decode('utf-16-le')
                                    if not match in matches[position]:
                                        matches[position].append(match)
                                        yield (
                                            0,
                                            (
                                                format_hints.Hex(offset),
                                                format_hints.Hex(size),
                                                self.format_match(matches),
                                            ),
                                        )        
                                position = 0  
                            i += 1                        
                    except exceptions.InvalidAddressException:
                        vollog.debug(
                            "Unable to read {}'s address {} to {}".format(
                                proc_layer_name,
                                offset,
                                file_handle.preferred_filename,
                            )
                        )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get("pid", None)])
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Constructed_Password", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
