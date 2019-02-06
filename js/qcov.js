const qbdi = require("./frida-qbdi");
qbdi.import();

rpc.exports = {

    init: function(name) {
        init_qbdi(name);
    }
}


function init_qbdi(name) {
    var modules = Process.enumerateModulesSync();
    send({"type": "module_map", "modules": modules});

    var module_map = new ModuleMap();

    var vm = new QBDI();
    var state = vm.getGPRState();
    var stack = vm.allocateVirtualStack(state, 0x100000);

    vm.simulateCall(state, ptr(42).toRword());
    vm.addInstrumentedModule(name);

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

    var main_addr = Module.findExportByName(null, "main");
    vm.run(main_addr, ptr(42));

    send({"type": "done"});
}
