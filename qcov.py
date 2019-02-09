import click
import frida
import lief
from tabulate import tabulate

import os
import sys
import struct


class Qcov(object):

    def __init__(self, target, outfile, modules):
        self._device = None
        self._target = target
        self._outfile = outfile

        self._modules_table = None
        self._coverage_data = []

        self._pid = None

        devices = frida.get_device_manager().enumerate_devices()
        self._get_device(devices)

        res = self._parse_binary(target)
        self._bin_name, self._bin_entrypoint, self._bin_imagebase = res

        # If no modules are specified, instrument the binary's module.
        if len(modules) == 0:
            self._modules = [self._bin_name]
        else:
            self._modules = list(modules)

    def spawn(self):
        self._pid = self._device.spawn([self._target])
        process = self._device.attach(self._pid)

        with open(os.path.join(sys.path[0], "qcov_compiled.js"), "r") as f:
            script = process.create_script(f.read())

        script.on("message", self._process_message)
        script.load()

        script.exports.init(
            self._bin_name,
            self._bin_entrypoint,
            self._bin_imagebase,
            self._modules
        )
        device.resume(pid)

    def _parse_binary(self, b):
        click.echo("Parsing binary...")
        p = lief.parse(str(b))

        name = p.name
        imagebase = p.imagebase

        if p.format == lief.EXE_FORMATS.ELF:
            m = p.get_symbol("main")
            entrypoint = m.value
            name = p.name
        elif p.format == lief.EXE_FORMATS.MACHO:
            entrypoint = p.entrypoint
        else:
            click.echo("Unsupported format. Exiting...")
            os._exit(1)

        return name, entrypoint, imagebase

    def _get_device(self, devices):
        click.echo("Available devices:")
        self._list_devices(devices)

        click.echo()
        click.echo("Select device (by index): ", nl=False)
        selection = input()

        try:
            self._device = devices[int(selection)]
        except:
            click.echo("Please enter a valid device selection...")
            os._exit(1)

    def _list_devices(self, devices):
        devices_info = [(i.id, i.name, i.type) for i in devices]
        click.echo(tabulate(
            devices_info, headers=["id", "name", "type"], showindex=True))

    def _format_module_map(self, module_map):
        ret = []

        for count, i in enumerate(module_map):
            ret.append({
                "id": count,
                "base": int(i["base"], 0),
                "end": int(i["base"], 0) + i["size"],
                "path": i["path"]
            })

        return ret

    def _make_cov_file(self, module_table, coverage_data):
        ret = b""
        ret += b"DRCOV VERSION: 2\n"
        ret += b"DRCOV FLAVOR: qcov\n"

        ret += "Module Table: version 2, count {}\n".format(
            len(module_table)).encode()
        ret += b"Columns: id, base, end, entry, checksum, timestamp, path\n"

        for i in module_table:
            ret += " {}, {}, {}, ".format(
                i["id"], hex(i["base"]), hex(i["end"])).encode()
            ret += "0x0000000000000000, 0x00000000, 0x00000000, {}\n".format(
                i["path"]).encode()

        ret += "BB Table: {} bbs\n".format(len(coverage_data)).encode()
        ret += b"".join(coverage_data)

        return ret

    def _process_message(self, message, data):
        if message["type"] == "send":
            if message["payload"]["type"] == "module_map":
                self._modules_table = self._format_module_map(
                    message["payload"]["modules"]
                )
            elif message["payload"]["type"] == "coverage":
                bb_start = int(message["payload"]["bb_start"])
                bb_end = int(message["payload"]["bb_end"])
                path = message["payload"]["path"]

                for i in self._modules_table:
                    if i["path"] == path:
                        module_id = i["id"]
                        start = bb_start - i["base"]
                        size = bb_end - bb_start

                self._coverage_data.append(struct.pack(
                    "=IHH", start, size, module_id
                ))

            elif message["payload"]["type"] == "done":
                self._device.kill(self._pid)
                click.echo("Writing coverage data...")
                self._outfile.write(self._make_cov_file(
                    self._modules_table, self._coverage_data
                ))
                self._outfile.close()
                os._exit(0)


@click.command(
    help="Get code coverage information with QBDI."
)
@click.argument("target", type=click.Path(exists=True))
@click.option("-o", "--outfile", type=click.File("wb"))
@click.option("-m", "--modules", type=str, multiple=True)
def cli(target, outfile, modules):
    qcov = Qcov(target, outfile, modules)
    qcov.spawn()


if __name__ == "__main__":
    cli()
