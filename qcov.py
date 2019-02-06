import click
import frida
import lief
from tabulate import tabulate

import os
import sys
import struct


modules_global = None
coverage_data = []
cov_file = None

device = None
pid = None


def process_message(message, data):
    global modules_global
    global coverage_data

    if message["type"] == "send":
        if message["payload"]["type"] == "module_map":
            modules_global = format_module_map(message["payload"]["modules"])
        elif message["payload"]["type"] == "coverage":
            bb_start = int(message["payload"]["bb_start"])
            bb_end = int(message["payload"]["bb_end"])
            path = message["payload"]["path"]

            for i in modules_global:
                if i["path"] == path:
                    module_id = i["id"]
                    start = bb_start - i["base"]
                    size = bb_end - bb_start

            coverage_data.append(struct.pack("=IHH", start, size, module_id))

        elif message["payload"]["type"] == "done":
            device.kill(pid)
            click.echo("Writing coverage data...")
            cov_file.write(make_cov_file(modules_global, coverage_data))
            os._exit(0)


def format_module_map(module_map):
    ret = []

    for count, i in enumerate(module_map):
        ret.append({
            "id": count,
            "base": int(i["base"], 0),
            "end": int(i["base"], 0) + i["size"],
            "path": i["path"]
        })

    return ret


def make_cov_file(module_table, coverage_data):
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


def get_device(devices):
    click.echo("Available devices:")
    list_devices(devices)

    click.echo()
    click.echo("Select device (by index): ", nl=False)
    selection = input()

    try:
        return devices[int(selection)]
    except:
        click.echo("Please enter a valid device selection...")
        os._exit(1)


def list_devices(devices):
    devices_info = [(i.id, i.name, i.type) for i in devices]
    click.echo(tabulate(
        devices_info, headers=["id", "name", "type"], showindex=True))


@click.command(
    help="Get code coverage information with QBDI."
)
@click.argument("target", type=click.Path(exists=True))
@click.option("-o", "--outfile", type=click.File("wb"))
def cli(target, outfile):

    global modules_global
    global cov_file
    global device
    global pid

    cov_file = outfile

    devices = frida.get_device_manager().enumerate_devices()
    device = get_device(devices)

    click.echo("Parsing binary...")
    p = lief.parse(str(target))

    pid = device.spawn([target])
    process = device.attach(pid)

    with open(os.path.join(sys.path[0], "qcov_compiled.js"), "r") as f:
        script = process.create_script(f.read())

    script.on("message", process_message)
    script.load()

    script.exports.init("hello", p.entrypoint, p.imagebase)
    device.resume(pid)


if __name__ == "__main__":
    cli()
