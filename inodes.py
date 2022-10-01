import logging, datetime, stat
from typing import Callable, Iterable, List, Any
from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class Inodes(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists inodes metadata for all processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.VersionRequirement(name='linuxutils', component=linux.LinuxUtilities, version=(2, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         description='Filter on specific process IDs',
                                         element_type=int,
                                         optional=True)
        ]

    @classmethod
    def inodes_metadata(cls, context: interfaces.context.ContextInterface, symbol_table: str,
                        task: interfaces.objects.ObjectInterface):
        fd_table = task.files.get_fds()

        if fd_table == 0:
            return

        max_fds = task.files.get_max_fds()
        # corruption check
        if max_fds > 500000:
            return

        file_type = symbol_table + constants.BANG + 'file'
        fds = utility.array_of_pointers(fd_table, count=max_fds, subtype=file_type, context=context)

        for fd in fds:
            if fd:
                # Getting the file full path
                full_path = linux.LinuxUtilities.path_for_file(context, task, fd)
                dentry = fd.get_dentry()

                # INODE EXTRACTION#
                if dentry != 0:
                    inode_object = dentry.d_inode
                    inode_num = inode_object.i_ino
                    file_size = inode_object.i_size  # file size in bytes
                    imode = stat.filemode(inode_object.i_mode)  # file type & Permissions

                    # Timestamps
                    ctime = datetime.datetime.fromtimestamp(inode_object.i_ctime.tv_sec)  # last change time
                    mtime = datetime.datetime.fromtimestamp(inode_object.i_mtime.tv_sec)  # last modify time
                    atime = datetime.datetime.fromtimestamp(inode_object.i_atime.tv_sec)  # last access time

                    yield full_path, inode_num, imode, ctime, mtime, atime, file_size

    def _generator(self, tasks):
        symbol_table = None
        for task in tasks:
            if symbol_table is None:
                if constants.BANG not in task.vol.type_name:
                    raise ValueError("Task is not part of a symbol table")
                symbol_table = task.vol.type_name.split(constants.BANG)[0]
            name = utility.array_to_string(task.comm)
            pid = int(task.pid)
            for full_path, inode_num, imode, ctime, mtime, atime, file_size in self.inodes_metadata(self.context,
                                                                                                    symbol_table,
                                                                                                    task):
                yield 0, (pid, name, inode_num, imode, full_path, ctime, mtime, atime, file_size)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        return renderers.TreeGrid([
            ("PID", int),
            ("Process", str),
            ("Inode", int),
            ("Mode", str),
            ("File", str),
            ("LastChange", datetime.datetime),
            ("LastModify", datetime.datetime),
            ("LastAccessed", datetime.datetime),
            ("Size", int),
        ],
            self._generator(
                pslist.PsList.list_tasks(self.context,
                                         self.config['kernel'],
                                         filter_func=filter_func)))

    def generate_timeline(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        for row in self._generator(
                pslist.PsList.list_tasks(self.context,
                                         self.config['kernel'],
                                         filter_func=filter_func)):
            _depth, row_data = row
            description = f"Process {row_data[1]} ({row_data[0]}) Open \"{row_data[4]}\""
            yield description, timeliner.TimeLinerType.CHANGED, row_data[5]
            yield description, timeliner.TimeLinerType.MODIFIED, row_data[6]
            yield description, timeliner.TimeLinerType.ACCESSED, row_data[7]
