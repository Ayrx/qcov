const qbdi = require("./frida-qbdi");
qbdi.import();

rpc.exports = {

    init: function(name, entrypoint, imagebase, modules_to_instrument) {
        init_qbdi(name, entrypoint, imagebase, modules_to_instrument);
    }
}


function init_qbdi(name, entrypoint, imagebase, modules_to_instrument) {
    var modules = Process.enumerateModulesSync();
    send({"type": "module_map", "modules": modules});

    var module_map = new ModuleMap();

    var vm = new QBDI();
    var state = vm.getGPRState();
    var stack = vm.allocateVirtualStack(state, 0x100000);

    vm.simulateCall(state, ptr(42).toRword());

    for (var i in modules_to_instrument) {
        console.log("Instrumenting module: " + modules_to_instrument[i]);
        vm.addInstrumentedModule(modules_to_instrument[i]);
    }

    var bb_callback = vm.newVMCallback(function(vm, evt, gpr, fpr, data) {
        send({
            "type": "coverage",
            "bb_start": evt.basicBlockStart,
            "bb_end": evt.basicBlockEnd,
            "path": module_map.find(ptr(evt.basicBlockStart)).path
        })
        VMAction.CONTINUE;
    });
    vm.addVMEventCB(VMEvent.BASIC_BLOCK_NEW, bb_callback, null);

    var process_base = Process.findModuleByName(name).base
    var address_offset = process_base.sub(imagebase)
    var actual_entrypoint = address_offset.add(entrypoint);

    vm.run(actual_entrypoint, ptr(42));
	vm.alignedFree(stack);

    send({"type": "done"});

	recv({}).wait();
}
