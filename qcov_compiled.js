(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){
/*
 * This file is part of QBDI.
 *
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';
/*
 * Usage:
 * $ frida -n Twitter -l frida-qbdi.js
 *
 */

var QBDI_MAJOR = 0;
var QBDI_MINOR = 6;
var QBDI_PATCH = 2;
var QBDI_MINIMUM_VERSION = QBDI_MAJOR << 8 | QBDI_MINOR << 4 | QBDI_PATCH;
/**data:QBDI_MINIMUM_VERSION
  Minimum version of QBDI to use Frida bindings
 */

if (typeof Duktape === 'object') {
  // Warn about duktape runtime (except on iOS...)
  if (Process.platform !== 'darwin' || Process.arch.indexOf("arm") !== 0) {
    console.warn("[!] Warning: using duktape runtime is much slower...");
    console.warn("    => Frida --enable-jit option should be used");
  }
} // Provide a generic and "safe" (no exceptions if symbol is not found) way to load
// a library and bind/create a native function


function Binder() {
  this.findLibrary = function (lib, paths) {
    if (lib === undefined) {
      return undefined;
    }

    var cpath = undefined;

    if (paths !== undefined) {
      var cnt = paths.length;
      var found = false; // try to find our library

      for (var i = 0; i < cnt; i++) {
        cpath = paths[i] + lib; // use Frida file interface to test if file exists...

        try {
          var fp = new File(cpath, "rb");
          fp.close();
          found = true;
          break;
        } catch (e) {
          continue;
        }
      }

      if (!found) {
        return undefined;
      }
    } else {
      cpath = lib;
    }

    return cpath;
  };

  function safeNativeFunction(cbk, ret, args) {
    var e = cbk();

    if (!e) {
      return undefined;
    }

    return new NativeFunction(e, ret, args);
  }

  Object.defineProperty(this, 'safeNativeFunction', {
    enumerable: false,
    value: safeNativeFunction
  });
}

Binder.prototype = {
  load: function (lib, paths) {
    var cpath = this.findLibrary(lib, paths);

    if (cpath === undefined) {
      var errmsg = lib + ' library not found...';
      console.error(errmsg);
      throw new Error(errmsg);
    } // load library


    var handle = System.dlopen(cpath);

    if (handle.isNull()) {
      var errmsg = 'Failed to load ' + cpath + ' (' + System.dlerror() + ')';
      console.error(errmsg);
      throw new Error(errmsg);
    }

    return cpath;
  },
  bind: function (name, ret, args) {
    return this.safeNativeFunction(function () {
      return Module.findExportByName(null, name);
    }, ret, args);
  }
};

function QBDIBinder() {
  /**attribute:QBDIBinder.QBDI_LIB
    QBDI library name
   */
  Object.defineProperty(this, 'QBDI_LIB', {
    enumerable: true,
    get: function () {
      return {
        'linux': 'libQBDI.so',
        'darwin': 'libQBDI.dylib',
        'windows': 'QBDI.dll'
      }[Process.platform];
    }
  }); // paths where QBDI library may be

  Object.defineProperty(this, 'QBDI_PATHS', {
    enumerable: true,
    get: function () {
      return [// UNIX default paths
      '/usr/lib/', '/usr/local/lib/', // advised Android path
      '/data/local/tmp/', // in case of a local archive
      './', './lib', // Windows default path
      'C:\\Program Files\\QBDI ' + QBDI_MAJOR + '.' + QBDI_MINOR + '.' + QBDI_PATCH + '\\lib\\'];
    }
  });
  Binder.call(this);
}

QBDIBinder.prototype = Object.create(Binder.prototype, {
  bind: {
    value: function (name, ret, args) {
      var libpath = this.QBDI_LIB;
      return this.safeNativeFunction(function () {
        return Module.findExportByName(libpath, name);
      }, ret, args);
    },
    enumerable: true
  },
  load: {
    value: function () {
      return Binder.prototype.load.apply(this, [this.QBDI_LIB, this.QBDI_PATHS]);
    },
    enumerable: true
  }
});
QBDIBinder.prototype.constructor = Binder;

var _binder = new Binder();

var _qbdibinder = new QBDIBinder(); // Needed to load QBDI


var System_C = Object.freeze({
  LoadLibraryEx: _binder.bind('LoadLibraryExA', 'pointer', ['pointer', 'int', 'int']),
  GetLastError: _binder.bind('GetLastError', 'int', []),
  dlopen: _binder.bind('dlopen', 'pointer', ['pointer', 'int']),
  dlerror: _binder.bind('dlerror', 'pointer', []),
  free: _binder.bind('free', 'void', ['pointer'])
});
var System = Object.freeze({
  dlerror: function () {
    if (Process.platform === "windows") {
      var val = System_C.GetLastError();

      if (val === undefined) {
        return undefined;
      }

      return val.toString();
    }

    var strPtr = System_C.dlerror();
    return Memory.readCString(strPtr);
  },
  dlopen: function (library) {
    var RTLD_LOCAL = 0x0;
    var RTLD_LAZY = 0x1;
    var path = Memory.allocUtf8String(library);

    if (Process.platform === "windows") {
      return System_C.LoadLibraryEx(path, 0, 0);
    }

    return System_C.dlopen(path, RTLD_LOCAL | RTLD_LAZY);
  },
  free: function (ptr) {
    System_C.free(ptr);
  }
}); // Load QBDI library

var QBDI_LIB_FULLPATH = _qbdibinder.load();
/**data:QBDI_LIB_FULLPATH
  Fullpath of the QBDI library
 */
// Define rword type and interfaces

/**data:rword
  An alias to Frida uint type with the size of general registers (**uint64** or **uint32**)
 */


var rword = Process.pointerSize === 8 ? 'uint64' : 'uint32';
Memory.readRword = Process.pointerSize === 8 ? Memory.readU64 : Memory.readU32; // Convert a number to its register-sized representation

/**function:NativePointer.prototype.toRword()
  Convert a NativePointer into a type with the size of a register (``Number`` or ``UInt64``).
 */

NativePointer.prototype.toRword = function () {
  // Nothing better really ?
  if (Process.pointerSize === 8) {
    return uint64("0x" + this.toString(16));
  }

  return parseInt(this.toString(16), 16);
};
/**function:Number.prototype.toRword()
  Convert a number into a type with the size of a register (``Number`` or ``UInt64``).
  Can't be used for numbers > 32 bits, would cause weird results due to IEEE-754.
 */


Number.prototype.toRword = function () {
  if (this > 0x100000000) {
    throw new TypeError('For integer > 32 bits, please use Frida uint64 type.');
  }

  if (Process.pointerSize === 8) {
    return uint64(this);
  }

  return this;
};
/**function:UInt64.prototype.toRword()
  An identity function (returning the same ``UInt64`` object).
  It exists only to provide a unified **toRword** interface.
 */


UInt64.prototype.toRword = function () {
  return this;
}; // Some helpers


String.prototype.leftPad = function (paddingValue, paddingLength) {
  paddingLength = paddingLength || paddingValue.length;

  if (paddingLength < this.length) {
    return String(this);
  }

  return String(paddingValue + this).slice(-paddingLength);
};
/**function:String.prototype.toRword()
  Convert a String into a type with the size of a register (``Number`` or ``UInt64``).
 */


String.prototype.toRword = function () {
  return ptr(this).toRword();
};
/**function:hexPointer(ptr)
  This function is used to pretty print a pointer, padded with 0 to the size of a register.

  :param ptr: Pointer you want to pad

  :returns: pointer value as padded string (ex: "0x00004242")
  :rtype: String
 */


function hexPointer(ptr) {
  return ptr.toString(16).leftPad("0000000000000000", Process.pointerSize * 2);
} //


var QBDI_C = Object.freeze({
  // VM
  initVM: _qbdibinder.bind('qbdi_initVM', 'void', ['pointer', 'pointer', 'pointer']),
  terminateVM: _qbdibinder.bind('qbdi_terminateVM', 'void', ['pointer']),
  addInstrumentedRange: _qbdibinder.bind('qbdi_addInstrumentedRange', 'void', ['pointer', rword, rword]),
  addInstrumentedModule: _qbdibinder.bind('qbdi_addInstrumentedModule', 'uchar', ['pointer', 'pointer']),
  addInstrumentedModuleFromAddr: _qbdibinder.bind('qbdi_addInstrumentedModuleFromAddr', 'uchar', ['pointer', rword]),
  instrumentAllExecutableMaps: _qbdibinder.bind('qbdi_instrumentAllExecutableMaps', 'uchar', ['pointer']),
  removeInstrumentedRange: _qbdibinder.bind('qbdi_removeInstrumentedRange', 'void', ['pointer', rword, rword]),
  removeInstrumentedModule: _qbdibinder.bind('qbdi_removeInstrumentedModule', 'uchar', ['pointer', 'pointer']),
  removeInstrumentedModuleFromAddr: _qbdibinder.bind('qbdi_removeInstrumentedModuleFromAddr', 'uchar', ['pointer', rword]),
  removeAllInstrumentedRanges: _qbdibinder.bind('qbdi_removeAllInstrumentedRanges', 'void', ['pointer']),
  run: _qbdibinder.bind('qbdi_run', 'uchar', ['pointer', rword, rword]),
  call: _qbdibinder.bind('qbdi_call', 'uchar', ['pointer', 'pointer', rword, 'uint32', rword, rword, rword, rword, rword, rword, rword, rword, rword, rword]),
  getGPRState: _qbdibinder.bind('qbdi_getGPRState', 'pointer', ['pointer']),
  getFPRState: _qbdibinder.bind('qbdi_getFPRState', 'pointer', ['pointer']),
  setGPRState: _qbdibinder.bind('qbdi_setGPRState', 'void', ['pointer', 'pointer']),
  setFPRState: _qbdibinder.bind('qbdi_setFPRState', 'void', ['pointer', 'pointer']),
  addMnemonicCB: _qbdibinder.bind('qbdi_addMnemonicCB', 'uint32', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']),
  addMemAccessCB: _qbdibinder.bind('qbdi_addMemAccessCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer']),
  addMemAddrCB: _qbdibinder.bind('qbdi_addMemAddrCB', 'uint32', ['pointer', rword, 'uint32', 'pointer', 'pointer']),
  addMemRangeCB: _qbdibinder.bind('qbdi_addMemRangeCB', 'uint32', ['pointer', rword, rword, 'uint32', 'pointer', 'pointer']),
  addCodeCB: _qbdibinder.bind('qbdi_addCodeCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer']),
  addCodeAddrCB: _qbdibinder.bind('qbdi_addCodeAddrCB', 'uint32', ['pointer', rword, 'uint32', 'pointer', 'pointer']),
  addCodeRangeCB: _qbdibinder.bind('qbdi_addCodeRangeCB', 'uint32', ['pointer', rword, rword, 'uint32', 'pointer', 'pointer']),
  addVMEventCB: _qbdibinder.bind('qbdi_addVMEventCB', 'uint32', ['pointer', 'uint32', 'pointer', 'pointer']),
  deleteInstrumentation: _qbdibinder.bind('qbdi_deleteInstrumentation', 'uchar', ['pointer', 'uint32']),
  deleteAllInstrumentations: _qbdibinder.bind('qbdi_deleteAllInstrumentations', 'void', ['pointer']),
  getInstAnalysis: _qbdibinder.bind('qbdi_getInstAnalysis', 'pointer', ['pointer', 'uint32']),
  recordMemoryAccess: _qbdibinder.bind('qbdi_recordMemoryAccess', 'uchar', ['pointer', 'uint32']),
  getInstMemoryAccess: _qbdibinder.bind('qbdi_getInstMemoryAccess', 'pointer', ['pointer', 'pointer']),
  getBBMemoryAccess: _qbdibinder.bind('qbdi_getBBMemoryAccess', 'pointer', ['pointer', 'pointer']),
  // Memory
  allocateVirtualStack: _qbdibinder.bind('qbdi_allocateVirtualStack', 'uchar', ['pointer', 'uint32', 'pointer']),
  alignedAlloc: _qbdibinder.bind('qbdi_alignedAlloc', 'pointer', ['uint32', 'uint32']),
  alignedFree: _qbdibinder.bind('qbdi_alignedFree', 'void', ['pointer']),
  simulateCall: _qbdibinder.bind('qbdi_simulateCall', 'void', ['pointer', rword, 'uint32', rword, rword, rword, rword, rword, rword, rword, rword, rword, rword]),
  getModuleNames: _qbdibinder.bind('qbdi_getModuleNames', 'pointer', ['pointer']),
  // Logs
  addLogFilter: _qbdibinder.bind('qbdi_addLogFilter', 'void', ['pointer', 'uint32']),
  // Helpers
  getVersion: _qbdibinder.bind('qbdi_getVersion', 'pointer', ['pointer']),
  getGPR: _qbdibinder.bind('qbdi_getGPR', rword, ['pointer', 'uint32']),
  setGPR: _qbdibinder.bind('qbdi_setGPR', 'void', ['pointer', 'uint32', rword]),
  getMemoryAccessStructDesc: _qbdibinder.bind('qbdi_getMemoryAccessStructDesc', 'pointer', []),
  getVMStateStructDesc: _qbdibinder.bind('qbdi_getVMStateStructDesc', 'pointer', []),
  getOperandAnalysisStructDesc: _qbdibinder.bind('qbdi_getOperandAnalysisStructDesc', 'pointer', []),
  getInstAnalysisStructDesc: _qbdibinder.bind('qbdi_getInstAnalysisStructDesc', 'pointer', []),
  precacheBasicBlock: _qbdibinder.bind('qbdi_precacheBasicBlock', 'uchar', ['pointer', rword]),
  clearCache: _qbdibinder.bind('qbdi_clearCache', 'void', ['pointer', rword, rword]),
  clearAllCache: _qbdibinder.bind('qbdi_clearAllCache', 'void', ['pointer'])
}); // Init some globals

if (Process.arch === 'x64') {
  /**data:GPR_NAMES
    An array holding register names.
   */

  /**data:REG_RETURN
    A constant string representing the register carrying the return value of a function.
   */

  /**data:REG_PC
    String of the instruction pointer register.
   */

  /**data:REG_SP
    String of the stack pointer register.
   */
  var GPR_NAMES = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RBP", "RSP", "RIP", "EFLAGS"];
  var REG_RETURN = "RAX";
  var REG_PC = "RIP";
  var REG_SP = "RSP";
} else if (Process.arch === 'arm') {
  var GPR_NAMES = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R12", "FP", "SP", "LR", "PC", "CPSR"];
  var REG_RETURN = "R0";
  var REG_PC = "PC";
  var REG_SP = "SP";
}
/**data:VMError
 */


var VMError = Object.freeze({
  /**attribute:VMError.INVALID_EVENTID
    Returned event is invalid.
   */
  INVALID_EVENTID: 0xffffffff
});
/**data:SyncDirection
  Synchronisation direction between Frida and QBDI GPR contexts
 */

var SyncDirection = Object.freeze({
  /**attribute:SyncDirection.QBDI_TO_FRIDA
    Constant variable used to synchronize QBDI's context to Frida's.
     .. warning:: This is currently not supported due to the lack of context updating in Frida.
   */
  QBDI_TO_FRIDA: 0,

  /**attribute:SyncDirection.FRIDA_TO_QBDI
    Constant variable used to synchronize Frida's context to QBDI's.
   */
  FRIDA_TO_QBDI: 1
});
/**data:VMAction
  The callback results.
 */

var VMAction = Object.freeze({
  /**attribute:VMAction.CONTINUE
    The execution of the basic block continues.
   */
  CONTINUE: 0,

  /**attribute:VMAction.BREAK_TO_VM
    The execution breaks and returns to the VM causing a complete reevaluation of
    the execution state. A :js:data:`VMAction.BREAK_TO_VM` is needed to ensure that modifications of
    the Program Counter or the program code are taken into account.
   */
  BREAK_TO_VM: 1,

  /**attribute:VMAction.STOP
    Stops the execution of the program. This causes the run function to return early.
   */
  STOP: 2
});
/**data:InstPosition
  Position relative to an instruction.
*/

var InstPosition = Object.freeze({
  /**attribute:InstPosition.PREINST
    Positioned **before** the instruction..
   */
  PREINST: 0,

  /**attribute:InstPosition.POSTINST
    Positioned **after** the instruction..
   */
  POSTINST: 1
});
/**data:VMEvent
  Events triggered by the virtual machine.
*/

var VMEvent = Object.freeze({
  /**attribute:VMEvent.SEQUENCE_ENTRY
    Triggered when the execution enters a sequence.
   */
  SEQUENCE_ENTRY: 1,

  /**attribute:VMEvent.SEQUENCE_EXIT
    Triggered when the execution exits from the current sequence.
   */
  SEQUENCE_EXIT: 1 << 1,

  /**attribute:VMEvent.BASIC_BLOCK_ENTRY
    Triggered when the execution enters a basic block.
   */
  BASIC_BLOCK_ENTRY: 1 << 2,

  /**attribute:VMEvent.BASIC_BLOCK_EXIT
    Triggered when the execution exits from the current basic block.
   */
  BASIC_BLOCK_EXIT: 1 << 3,

  /**attribute:VMEvent.BASIC_BLOCK_NEW
    Triggered when the execution enters a new (~unknown) basic block.
   */
  BASIC_BLOCK_NEW: 1 << 4,

  /**attribute:VMEvent.EXEC_TRANSFER_CALL
    Triggered when the ExecBroker executes an execution transfer.
   */
  EXEC_TRANSFER_CALL: 1 << 5,

  /**attribute:VMEvent.EXEC_TRANSFER_RETURN
     Triggered when the ExecBroker returns from an execution transfer.
   */
  EXEC_TRANSFER_RETURN: 1 << 6,

  /**attribute:VMEvent.SYSCALL_ENTRY
    Not implemented.
   */
  SYSCALL_ENTRY: 1 << 7,

  /**attribute:VMEvent.SYSCALL_EXIT
    Not implemented.
   */
  SYSCALL_EXIT: 1 << 8,

  /**attribute:VMEvent.SIGNAL
    Not implemented.
   */
  SIGNAL: 1 << 9
});
/**data:MemoryAccessType
  Memory access type (read / write / ...)
*/

var MemoryAccessType = Object.freeze({
  /**attribute:MemoryAccessType.MEMORY_READ
    Memory read access.
   */
  MEMORY_READ: 1,

  /**attribute:MemoryAccessType.MEMORY_WRITE
    Memory write access.
   */
  MEMORY_WRITE: 2,

  /**attribute:MemoryAccessType.MEMORY_READ_WRITE
    Memory read/write access.
   */
  MEMORY_READ_WRITE: 3
});
/**data:RegisterAccessType
  Register access type (read / write / rw)
*/

var RegisterAccessType = Object.freeze({
  /**attribute:RegisterAccessType.REGISTER_READ
    Register is read.
   */
  REGISTER_READ: 1,

  /**attribute:RegisterAccessType.REGISTER_WRITE
    Register is written.
   */
  REGISTER_WRITE: 2,

  /**attribute:RegisterAccessType.REGISTER_READ_WRITE
    Register is read/written.
   */
  REGISTER_READ_WRITE: 3
});
/**data:OperandType
  Register access type (read / write / rw)
*/

var OperandType = Object.freeze({
  /**attribute:OperandType.OPERAND_INVALID
    Invalid operand.
   */
  OPERAND_INVALID: 0,

  /**attribute:OperandType.OPERAND_IMM
    Immediate operand.
   */
  OPERAND_IMM: 1,

  /**attribute:OperandType.OPERAND_GPR
    General purpose register operand.
   */
  OPERAND_GPR: 2,

  /**attribute:OperandType.OPERAND_PRED
    Predicate special operand.
   */
  OPERAND_PRED: 3
});
/**data:AnalysisType
  Properties to retrieve during an instruction analysis.
*/

var AnalysisType = Object.freeze({
  /**attribute:AnalysisType.ANALYSIS_INSTRUCTION
    Instruction analysis (address, mnemonic, ...).
   */
  ANALYSIS_INSTRUCTION: 1,

  /**attribute:AnalysisType.ANALYSIS_DISASSEMBLY
    Instruction disassembly.
   */
  ANALYSIS_DISASSEMBLY: 1 << 1,

  /**attribute:AnalysisType.ANALYSIS_OPERANDS
    Instruction operands analysis.
   */
  ANALYSIS_OPERANDS: 1 << 2,

  /**attribute:AnalysisType.ANALYSIS_SYMBOL
    Instruction nearest symbol (and offset).
   */
  ANALYSIS_SYMBOL: 1 << 3
});
/**class:QBDI
 State class
*/

function State(state) {
  var statePtr = null;

  function initialize(s) {
    if (!NativePointer.prototype.isPrototypeOf(s) || s.isNull()) {
      throw new TypeError('Invalid state pointer');
    }

    statePtr = s;
  }

  Object.defineProperty(this, 'ptr', {
    enumerable: false,
    get: function () {
      return statePtr;
    }
  });

  this.toRword = function () {
    return statePtr.toRword();
  };

  this.toString = function () {
    return statePtr.toString();
  };

  initialize.call(this, state);
}
/**class:QBDI
 GPR State class
*/


function GPRState(state) {
  function getGPRId(rid) {
    if (typeof rid === 'string') {
      rid = GPR_NAMES.indexOf(rid.toUpperCase());
    }

    if (rid < 0 || rid > GPR_NAMES.length) {
      return undefined;
    }

    return rid;
  }

  this.getRegister = function (rid) {
    /**:GPRState.prototype.getRegister(rid)
      This function is used to get the value of a specific register.
       :param rid: Register (register name or ID can be used e.g : "RAX", "rax", 0)
       :returns: GPR value (ex: 0x42)
      :rtype: ``NativePointer``
     */
    var rid = getGPRId(rid);

    if (rid === null) {
      return undefined;
    }

    return ptr(QBDI_C.getGPR(this.ptr, rid));
  };

  this.setRegister = function (rid, value) {
    /**:GPRState.prototype.setRegister(rid, value)
      This function is used to set the value of a specific register.
       :param rid: Register (register name or ID can be used e.g : "RAX", "rax", 0)
      :param value: Register value (use **strings** for big integers)
    */
    var rid = getGPRId(rid);

    if (rid !== null) {
      QBDI_C.setGPR(this.ptr, rid, value.toRword());
    }
  };

  this.getRegisters = function () {
    /**:GPRState.prototype.getRegisters()
      This function is used to get values of all registers.
       :returns: GPRs of current context (ex: {"RAX":0x42, ...})
      :rtype: {String:rword, ...}
    */
    var regCnt = GPR_NAMES.length;
    var gprs = {};

    for (var i = 0; i < regCnt; i++) {
      gprs[GPR_NAMES[i]] = this.getRegister(i);
    }

    return gprs;
  };

  this.setRegisters = function (gprs) {
    /**:GPRState.prototype.setRegisters(gprs)
      This function is used to set values of all registers.
       :param gprs: Array of register values
    */
    var regCnt = GPR_NAMES.length;

    for (var i = 0; i < regCnt; i++) {
      this.setRegister(i, gprs[GPR_NAMES[i]]);
    }
  };

  this.synchronizeRegister = function (FridaCtx, rid, direction) {
    /**:GPRState.prototype.synchronizeRegister(FridaCtx, rid, direction)
     This function is used to synchronise a specific register between Frida and QBDI.
      :param FridaCtx: Frida context
     :param rid: Register (register name or ID can be used e.g : "RAX", "rax", 0)
     :param direction: Synchronization direction. (:js:data:`FRIDA_TO_QBDI` or :js:data:`QBDI_TO_FRIDA`)
      .. warning:: Currently QBDI_TO_FRIDA is experimental. (E.G : RIP cannot be synchronized)
    */
    if (direction === SyncDirection.FRIDA_TO_QBDI) {
      this.setRegister(rid, FridaCtx[rid.toLowerCase()].toRword());
    } else {
      // FRIDA_TO_QBDI
      FridaCtx[rid.toLowerCase()] = ptr(this.getRegister(rid).toString());
    }
  };

  this.synchronizeContext = function (FridaCtx, direction) {
    /**:GPRState.prototype.synchronizeContext(FridaCtx, direction)
     This function is used to synchronise context between Frida and QBDI.
      :param FridaCtx: Frida context
     :param direction: Synchronization direction. (:js:data:`FRIDA_TO_QBDI` or :js:data:`QBDI_TO_FRIDA`)
      .. warning:: Currently QBDI_TO_FRIDA is not implemented (due to Frida limitations).
    */
    for (var i in GPR_NAMES) {
      if (GPR_NAMES[i] === "EFLAGS") {
        continue;
      }

      this.synchronizeRegister(FridaCtx, GPR_NAMES[i], direction);
    }

    if (direction === SyncDirection.QBDI_TO_FRIDA) {
      throw new Error('Not implemented (does not really work due to Frida)');
    }
  };

  this.pp = function (color) {
    /**:GPRState.prototype.pp([color])
      Pretty print QBDI context.
       :param [color]: Will print a colored version of the context if set.
       :returns: dump of all GPRs in a pretty format
      :rtype: String
    */
    var RED = color ? "\x1b[31m" : "";
    var GREEN = color ? "\x1b[32m" : "";
    var RESET = color ? "\x1b[0m" : "";
    var regCnt = GPR_NAMES.length;
    var regs = this.getRegisters();
    var line = "";

    for (var i = 0; i < regCnt; i++) {
      var name = GPR_NAMES[i];

      if (!(i % 4) && i) {
        line += '\n';
      }

      line += GREEN; // Will be overwritten by RED if necessary

      if (name === "RIP" | name === "PC") {
        line += RED;
      }

      line += name.leftPad("   ") + RESET + "=0x" + hexPointer(regs[name]) + " ";
    }

    return line;
  };

  this.dump = function (color) {
    /**:GPRState.prototype.dump([color])
      Pretty print and log QBDI context.
       :param [color]: Will print a colored version of the context if set.
    */
    console.log(this.pp(color));
  };

  State.call(this, state);
}

GPRState.prototype = Object.create(State.prototype);
GPRState.prototype.constructor = GPRState;

GPRState.validOrThrow = function (state) {
  if (!GPRState.prototype.isPrototypeOf(state)) {
    throw new TypeError('Invalid GPRState');
  }
};
/**class:QBDI
 FPR State class
*/


function FPRState(state) {
  State.call(this, state);
}

FPRState.prototype = Object.create(State.prototype);
FPRState.prototype.constructor = FPRState;

FPRState.validOrThrow = function (state) {
  if (!FPRState.prototype.isPrototypeOf(state)) {
    throw new TypeError('Invalid FPRState');
  }
};
/**class:QBDI
 QBDI VM class
*/


function QBDI() {
  // QBDI VM Instance pointer
  var vm = null; // Cache various remote structure descriptions

  var memoryAccessDesc = null;
  var operandAnalysisStructDesc = null;
  var instAnalysisStructDesc = null;
  var vmStateStructDesc = null; // Keep a reference to objects used as user callback data

  var userDataPtrMap = {};
  var userDataIIdMap = {};
  Object.defineProperty(this, 'ptr', {
    enumerable: false,
    get: function () {
      return vm;
    }
  });

  function parseStructDesc(ptr) {
    var desc = {};
    desc.size = Memory.readU32(ptr);
    ptr = ptr.add(4);
    desc.items = Memory.readU32(ptr);
    ptr = ptr.add(4);
    desc.offsets = [];

    for (var i = 0; i < desc.items; i++) {
      var offset = Memory.readU32(ptr);
      ptr = ptr.add(4);
      desc.offsets.push(offset);
    }

    Object.freeze(desc);
    return desc;
  } // VM


  function initVM() {
    /**:_QBDI
        Create a new instrumentation virtual machine using "**new QBDI()**"
         :returns:   QBDI virtual machine instance
        :rtype:     object
    */
    var vmPtr = Memory.alloc(Process.pointerSize);
    QBDI_C.initVM(vmPtr, NULL, NULL);
    return Memory.readPointer(vmPtr);
  }

  function terminateVM(v) {
    QBDI_C.terminateVM(v);
  }

  function initialize() {
    // Enforce a minimum QBDI version (API compatibility)
    if (!this.version || this.version.integer < QBDI_MINIMUM_VERSION) {
      throw new Error('Invalid QBDI version !');
    } // Create VM instance


    vm = initVM(); // Parse remote structure descriptions

    memoryAccessDesc = parseStructDesc(QBDI_C.getMemoryAccessStructDesc());
    operandAnalysisStructDesc = parseStructDesc(QBDI_C.getOperandAnalysisStructDesc());
    instAnalysisStructDesc = parseStructDesc(QBDI_C.getInstAnalysisStructDesc());
    vmStateStructDesc = parseStructDesc(QBDI_C.getVMStateStructDesc());
  } // add a destructor on garbage collection


  WeakRef.bind(QBDI, function dispose() {
    if (vm !== null) {
      terminateVM(vm);
    }
  });

  this.addInstrumentedRange = function (start, end) {
    /**:QBDI.prototype.addInstrumentedRange(start, end)
        Add an address range to the set of instrumented address ranges.
         :param start:  Start address of the range (included).
        :param end:    End address of the range (excluded).
    */
    QBDI_C.addInstrumentedRange(vm, start.toRword(), end.toRword());
  };

  this.addInstrumentedModule = function (name) {
    /**:QBDI.prototype.addInstrumentedModule(name)
        Add the executable address ranges of a module to the set of instrumented address ranges.
         :param name:   The module's name.
         :returns:   True if at least one range was added to the instrumented ranges.
        :rtype:     boolean
    */
    var namePtr = Memory.allocUtf8String(name);
    return QBDI_C.addInstrumentedModule(vm, namePtr) == true;
  };

  this.addInstrumentedModuleFromAddr = function (addr) {
    /**:QBDI.prototype.addInstrumentedModuleFromAddr(addr)
        Add the executable address ranges of a module to the set of instrumented address ranges. using an address belonging to the module.
         :param addr:   An address contained by module's range.
         :returns:   True if at least one range was removed from the instrumented ranges.
        :rtype:     boolean
    */
    return QBDI_C.addInstrumentedModuleFromAddr(vm, addr.toRword()) == true;
  };

  this.instrumentAllExecutableMaps = function () {
    /**:QBDI.prototype.instrumentAllExecutableMaps()
        Adds all the executable memory maps to the instrumented range set.
         :returns:   True if at least one range was added to the instrumented ranges.
        :rtype:     boolean
    */
    return QBDI_C.instrumentAllExecutableMaps(vm) == true;
  };

  this.removeInstrumentedRange = function (start, end) {
    /**:QBDI.prototype.removeInstrumentedRange(start, end)
        Remove an address range from the set of instrumented address ranges.
         :param start:  Start address of the range (included).
        :param end:    End address of the range (excluded).
    */
    QBDI_C.removeInstrumentedRange(vm, start.toRword(), end.toRword());
  };

  this.removeInstrumentedModule = function (name) {
    /**:QBDI.prototype.removeInstrumentedModule(name)
        Remove the executable address ranges of a module from the set of instrumented address ranges.
         :param name:   The module's name.
         :returns:   True if at least one range was added to the instrumented ranges.
        :rtype:     boolean
    */
    var namePtr = Memory.allocUtf8String(name);
    return QBDI_C.removeInstrumentedModule(vm, namePtr) == true;
  };

  this.removeInstrumentedModuleFromAddr = function (addr) {
    return QBDI_C.removeInstrumentedModuleFromAddr(vm, addr.toRword()) == true;
  };

  this.removeAllInstrumentedRanges = function () {
    QBDI_C.removeAllInstrumentedRanges(vm);
  };

  this.run = function (start, stop) {
    /**:QBDI.prototype.run(start, stop)
        Start the execution by the DBI from a given address (and stop when another is reached).
         :param start:  Address of the first instruction to execute.
        :param stop:   Stop the execution when this instruction is reached.
         :returns:   True if at least one block has been executed.
        :rtype:     boolean
    */
    return QBDI_C.run(vm, start.toRword(), stop.toRword()) == true;
  };

  this.getGPRState = function () {
    /**:QBDI.prototype.getGPRState(state)
        Obtain the current general register state.
         :returns:   An object containing the General Purpose Registers state.
        :rtype:     object
    */
    return new GPRState(QBDI_C.getGPRState(vm));
  };

  this.getFPRState = function () {
    /**:QBDI.prototype.getFPRState(state)
        Obtain the current floating point register state.
         :returns:   An object containing the Floating point Purpose Registers state.
        :rtype:     object
    */
    return new FPRState(QBDI_C.getFPRState(vm));
  };

  this.setGPRState = function (state) {
    /**:QBDI.prototype.setGPRState(state)
        Set the GPR state
         :param state:  Array of register values
    */
    GPRState.validOrThrow(state);
    QBDI_C.setGPRState(vm, state.ptr);
  };

  this.setFPRState = function (state) {
    /**:QBDI.prototype.setFPRState(state)
        Set the FPR state
         :param state:  Array of register values
    */
    FPRState.validOrThrow(state);
    QBDI_C.setFPRState(vm, state.ptr);
  };

  this.precacheBasicBlock = function (pc) {
    /**:QBDI.prototype.precacheBasicBlock(state)
        Pre-cache a known basic block.
         :param pc:  Start address of a basic block
         :returns: True if basic block has been inserted in cache.
        :rtype:     bool
    */
    return QBDI_C.precacheBasicBlock(vm, pc) == true;
  };

  this.clearCache = function (start, end) {
    /**:QBDI.prototype.precacheBasicBlock(state)
        Clear a specific address range from the translation cache.
         :param start:  Start of the address range to clear from the cache.
        :param end:    End of the address range to clear from the cache.
    */
    QBDI_C.clearCache(vm, start, end);
  };

  this.clearAllCache = function () {
    /**:QBDI.prototype.precacheBasicBlock(state)
        Clear the entire translation cache.
    */
    QBDI_C.clearAllCache(vm);
  }; // Retain (~reference) a user data object when an instrumentation is added.
  //
  // If a ``NativePointer`` is given, it will be used as raw user data and the
  // object will not be retained.


  function retainUserData(data, fn) {
    var dataPtr = data || NULL;
    var managed = false;

    if (!NativePointer.prototype.isPrototypeOf(data)) {
      dataPtr = Memory.alloc(4);
      managed = true;
    }

    var iid = fn(dataPtr);

    if (managed) {
      userDataPtrMap[dataPtr] = data;
      userDataIIdMap[iid] = dataPtr;
      Memory.writeU32(dataPtr, iid);
    }

    return iid;
  } // Retrieve a user data object from its ``NativePointer`` reference.
  // If pointer is NULL or no data object is found, the ``NativePointer``
  // object will be returned.


  function getUserData(dataPtr) {
    var data = dataPtr;

    if (!data.isNull()) {
      var d = userDataPtrMap[dataPtr];

      if (d !== undefined) {
        data = d;
      }
    }

    return data;
  } // Release references to a user data object using the correponding
  // instrumentation id.


  function releaseUserData(id) {
    var dataPtr = userDataIIdMap[id];

    if (dataPtr !== undefined) {
      delete userDataPtrMap[dataPtr];
      delete userDataIIdMap[id];
    }
  } // Release all references to user data objects.


  function releaseAllUserData() {
    userDataPtrMap = {};
    userDataIIdMap = {};
  }

  this.addMnemonicCB = function (mnem, pos, cbk, data) {
    /**:QBDI.prototype.addMnemonicCB(mnem, pos, cbk, data)
        Register a callback event if the instruction matches the mnemonic.
         :param mnem:   Mnemonic to match.
        :param pos:    Relative position of the event callback (PreInst / PostInst).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    var mnemPtr = Memory.allocUtf8String(mnem);
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addMnemonicCB(vm, mnemPtr, pos, cbk, dataPtr);
    });
  };

  this.addMemAccessCB = function (type, cbk, data) {
    /**:QBDI.prototype.addMemAccessCB(type, cbk, data)
        Register a callback event for every memory access matching the type bitfield made by the instruction in the range codeStart to codeEnd.
         :param type:   A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addMemAccessCB(vm, type, cbk, dataPtr);
    });
  };

  this.addMemAddrCB = function (addr, type, cbk, data) {
    /**:QBDI.prototype.addMemAddrCB(addr, type, cbk, data)
        Add a virtual callback which is triggered for any memory access at a specific address matching the access type.
        Virtual callbacks are called via callback forwarding by a gate callback triggered on every memory access. This incurs a high performance cost.
         :param addr:   Code address which will trigger the callback.
        :param type:   A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addMemAddrCB(vm, addr.toRword(), type, cbk, dataPtr);
    });
  };

  this.addMemRangeCB = function (start, end, type, cbk, data) {
    /**:QBDI.prototype.addMemRangeCB(start, end, type, cbk, data)
      Add a virtual callback which is triggered for any memory access in a specific address range matching the access type.
      Virtual callbacks are called via callback forwarding by a gate callback triggered on every memory access. This incurs a high performance cost.
       :param start:    Start of the address range which will trigger the callback.
      :param end:      End of the address range which will trigger the callback.
      :param type:     A mode bitfield: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
      :param cbk:      A function pointer to the callback.
      :param data:     User defined data passed to the callback.
       :returns: The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
      :rtype:   integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addMemRangeCB(vm, start.toRword(), end.toRword(), type, cbk, dataPtr);
    });
  };

  this.addCodeCB = function (pos, cbk, data) {
    /**:QBDI.prototype.addCodeCB(pos, cbk, data)
        Register a callback event for a specific instruction event.
         :param pos:    Relative position of the event callback (PreInst / PostInst).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addCodeCB(vm, pos, cbk, dataPtr);
    });
  };

  this.addCodeAddrCB = function (addr, pos, cbk, data) {
    /**:QBDI.prototype.addCodeAddrCB(addr, pos, cbk, data)
        Register a callback for when a specific address is executed.
         :param addr:   Code address which will trigger the callback.
        :param pos:    Relative position of the event callback (PreInst / PostInst).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addCodeAddrCB(vm, addr.toRword(), pos, cbk, dataPtr);
    });
  };

  this.addCodeRangeCB = function (start, end, pos, cbk, data) {
    /**:QBDI.prototype.addCodeRangeCB(start, end, pos, cbk, data)
        Register a callback for when a specific address range is executed.
         :param start:  Start of the address range which will trigger the callback.
        :param end:    End of the address range which will trigger the callback.
        :param pos:    Relative position of the event callback (PreInst / PostInst).
        :param cbk:    A function pointer to the callback.
        :param data:   User defined data passed to the callback.
         :returns:   The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
        :rtype:     integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addCodeRangeCB(vm, start.toRword(), end.toRword(), pos, cbk, dataPtr);
    });
  };

  this.addVMEventCB = function (mask, cbk, data) {
    /**:QBDI.prototype.addVMEventCB(mask, cbk, data)
      Register a callback event for a specific VM event.
       :param mask: A mask of VM event type which will trigger the callback.
      :param cbk:  A function pointer to the callback.
      :param data: User defined data passed to the callback.
       :returns: The id of the registered instrumentation (or VMError.INVALID_EVENTID in case of failure).
      :rtype:   integer
    */
    return retainUserData(data, function (dataPtr) {
      return QBDI_C.addVMEventCB(vm, mask, cbk, dataPtr);
    });
  };

  this.deleteInstrumentation = function (id) {
    /**:QBDI.prototype.deleteInstrumentation(id)
      Remove an instrumentation.
       :param id:   The id of the instrumentation to remove.
      :returns:     True if instrumentation has been removed.
      :rtype:       boolean
    */
    releaseUserData(id);
    return QBDI_C.deleteInstrumentation(vm, id) == true;
  };

  this.deleteAllInstrumentations = function () {
    /**:QBDI.prototype.deleteAllInstrumentations()
      Remove all the registered instrumentations.
    */
    releaseAllUserData();
    QBDI_C.deleteAllInstrumentations(vm);
  };

  function parseVMState(ptr) {
    var state = {};
    var p = ptr;
    state.event = Memory.readU8(p);
    p = ptr.add(vmStateStructDesc.offsets[1]);
    state.sequenceStart = Memory.readRword(p);
    p = ptr.add(vmStateStructDesc.offsets[2]);
    state.sequenceEnd = Memory.readRword(p);
    p = ptr.add(vmStateStructDesc.offsets[3]);
    state.basicBlockStart = Memory.readRword(p);
    p = ptr.add(vmStateStructDesc.offsets[4]);
    state.basicBlockEnd = Memory.readRword(p);
    p = ptr.add(vmStateStructDesc.offsets[5]);
    state.lastSignal = Memory.readRword(p);
    Object.freeze(state);
    return state;
  }

  function parseOperandAnalysis(ptr) {
    var analysis = {};
    var p = ptr;
    analysis.type = Memory.readU32(p);
    p = ptr.add(operandAnalysisStructDesc.offsets[1]);
    analysis.value = Memory.readRword(p);
    p = ptr.add(operandAnalysisStructDesc.offsets[2]);
    analysis.size = Memory.readU8(p);
    p = ptr.add(operandAnalysisStructDesc.offsets[3]);
    analysis.regOff = Memory.readU8(p);
    p = ptr.add(operandAnalysisStructDesc.offsets[4]);
    analysis.regCtxIdx = Memory.readU16(p);
    p = ptr.add(operandAnalysisStructDesc.offsets[5]);
    var regNamePtr = Memory.readPointer(p);

    if (regNamePtr.isNull()) {
      analysis.regName = undefined;
    } else {
      analysis.regName = Memory.readCString(regNamePtr);
    }

    p = ptr.add(operandAnalysisStructDesc.offsets[6]);
    analysis.regAccess = Memory.readU8(p);
    Object.freeze(analysis);
    return analysis;
  }

  function parseInstAnalysis(ptr) {
    var analysis = {};
    var p = ptr;
    analysis.mnemonic = Memory.readCString(Memory.readPointer(p));
    p = ptr.add(instAnalysisStructDesc.offsets[1]);
    analysis.disassembly = Memory.readCString(Memory.readPointer(p));
    p = ptr.add(instAnalysisStructDesc.offsets[2]);
    analysis.address = Memory.readRword(p);
    p = ptr.add(instAnalysisStructDesc.offsets[3]);
    analysis.instSize = Memory.readU32(p);
    p = ptr.add(instAnalysisStructDesc.offsets[4]);
    analysis.affectControlFlow = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[5]);
    analysis.isBranch = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[6]);
    analysis.isCall = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[7]);
    analysis.isReturn = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[8]);
    analysis.isCompare = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[9]);
    analysis.isPredicable = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[10]);
    analysis.mayLoad = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[11]);
    analysis.mayStore = Memory.readU8(p) == true;
    p = ptr.add(instAnalysisStructDesc.offsets[12]);
    var numOperands = Memory.readU8(p);
    p = ptr.add(instAnalysisStructDesc.offsets[13]);
    var operandsPtr = Memory.readPointer(p);
    analysis.operands = new Array(numOperands);

    for (var i = 0; i < numOperands; i++) {
      analysis.operands[i] = parseOperandAnalysis(operandsPtr);
      operandsPtr = operandsPtr.add(operandAnalysisStructDesc.size);
    }

    p = ptr.add(instAnalysisStructDesc.offsets[14]);
    var symbolPtr = Memory.readPointer(p);

    if (!symbolPtr.isNull()) {
      analysis.symbol = Memory.readCString(symbolPtr);
    } else {
      analysis.symbol = "";
    }

    p = ptr.add(instAnalysisStructDesc.offsets[15]);
    analysis.symbolOffset = Memory.readU32(p);
    p = ptr.add(instAnalysisStructDesc.offsets[16]);
    var modulePtr = Memory.readPointer(p);

    if (!modulePtr.isNull()) {
      analysis.module = Memory.readCString(modulePtr);
    } else {
      analysis.module = "";
    }

    Object.freeze(analysis);
    return analysis;
  }

  this.getInstAnalysis = function (type) {
    /**:QBDI.prototype.getInstAnalysis()
      Obtain the analysis of an instruction metadata. Analysis results are cached in the VM.
      The validity of the returned pointer is only guaranteed until the end of the callback, else a deepcopy of the structure is required.
       :param [type]: Properties to retrieve during analysis (default to ANALYSIS_INSTRUCTION | ANALYSIS_DISASSEMBLY).
       :returns: A InstAnalysis object containing the analysis result.
      :rtype:   Object
    */
    type = type || AnalysisType.ANALYSIS_INSTRUCTION | AnalysisType.ANALYSIS_DISASSEMBLY;
    var analysis = QBDI_C.getInstAnalysis(vm, type);

    if (analysis.isNull()) {
      return NULL;
    }

    return parseInstAnalysis(analysis);
  };

  this.recordMemoryAccess = function (type) {
    /**:QBDI.prototype.recordMemoryAccess(type)
      Obtain the memory accesses made by the last executed instruction. Return NULL and a size of 0 if the instruction made no memory access.
       :param type: Memory mode bitfield to activate the logging for: either MEMORY_READ, MEMORY_WRITE or both (MEMORY_READ_WRITE).
    */
    return QBDI_C.recordMemoryAccess(vm, type) == true;
  };

  function parseMemoryAccess(ptr) {
    var access = {};
    var p = ptr;
    access.instAddress = Memory.readRword(p);
    p = ptr.add(memoryAccessDesc.offsets[1]);
    access.accessAddress = Memory.readRword(p);
    p = ptr.add(memoryAccessDesc.offsets[2]);
    access.value = Memory.readRword(p);
    p = ptr.add(memoryAccessDesc.offsets[3]);
    access.size = Memory.readU8(p);
    p = ptr.add(memoryAccessDesc.offsets[4]);
    access.type = Memory.readU8(p);
    Object.freeze(access);
    return access;
  }

  function getMemoryAccess(f) {
    var accesses = [];
    var sizePtr = Memory.alloc(4);
    var accessPtr = f(vm, sizePtr);

    if (accessPtr.isNull()) {
      return [];
    }

    var cnt = Memory.readU32(sizePtr);
    var sSize = memoryAccessDesc.size;
    var p = accessPtr;

    for (var i = 0; i < cnt; i++) {
      var access = parseMemoryAccess(p);
      accesses.push(access);
      p = p.add(sSize);
    }

    System.free(accessPtr);
    return accesses;
  }

  this.getInstMemoryAccess = function () {
    /**:QBDI.prototype.getInstMemoryAccess()
      Obtain the memory accesses made by the last executed instruction. Return NULL and a size of 0 if the instruction made no memory access.
       :returns: An array of memory accesses made by the instruction.
      :rtype:   Array
    */
    return getMemoryAccess(QBDI_C.getInstMemoryAccess);
  };

  this.getBBMemoryAccess = function () {
    /**:QBDI.prototype.getBBMemoryAccess()
      Obtain the memory accesses made by the last executed basic block. Return NULL and a size of 0 if the basic block made no memory access.
     :returns:   An array of memory accesses made by the basic block.
    :rtype:     Array
    */
    return getMemoryAccess(QBDI_C.getBBMemoryAccess);
  }; // Memory


  this.allocateVirtualStack = function (state, stackSize) {
    /**:QBDI.prototype.allocateVirtualStack(gprs, stackSize)
      Allocate a new stack and setup the GPRState accordingly. The allocated stack needs to be freed with alignedFree().
       :param gprs:      Array of register values
      :param stackSize: Size of the stack to be allocated.
    */
    GPRState.validOrThrow(state);
    var stackPtr = Memory.alloc(Process.pointerSize);
    var ret = QBDI_C.allocateVirtualStack(state.ptr, stackSize, stackPtr);

    if (ret == false) {
      return NULL;
    }

    return Memory.readPointer(stackPtr);
  };

  this.alignedAlloc = function (size, align) {
    /**:QBDI.prototype.alignedAlloc(size, align)
      Allocate a block of memory of a specified sized with an aligned base address.
       :param size:  Allocation size in bytes.
      :param align: Base address alignement in bytes.
       :returns: Pointer to the allocated memory or NULL in case an error was encountered.
      :rtype: rword
    */
    return QBDI_C.alignedAlloc(size, align);
  };

  this.alignedFree = function (ptr) {
    QBDI_C.alignedFree(ptr);
  };

  function formatVAArgs(args) {
    if (args === undefined) {
      args = [];
    }

    var argsCnt = args.length; // We are limited to 10 arguments for now

    var fargs = new Array(10);
    var fargsCnt = fargs.length;

    for (var i = 0; i < fargsCnt; i++) {
      if (i < argsCnt) {
        fargs[i] = args[i].toRword();
      } else {
        fargs[i] = 0;
      }
    }

    return [argsCnt, fargs];
  }

  this.simulateCall = function (state, retAddr, args) {
    /**:QBDI.prototype.simulateCall(state, retAddr, [args])
      Simulate a call by modifying the stack and registers accordingly.
       :param state:     Array of register values
      :param retAddr:   Return address of the call to simulate.
      :param args:      A variadic list of arguments.
    */
    GPRState.validOrThrow(state);
    retAddr = retAddr.toRword();
    var fargs = formatVAArgs(args); // Use this weird construction to work around a bug in the duktape runtime

    var _simulateCall = function (a, b, c, d, e, f, g, h, i, j) {
      QBDI_C.simulateCall(state.ptr, retAddr, fargs[0], a, b, c, d, e, f, g, h, i, j);
    };

    _simulateCall.apply(null, fargs[1]);
  };

  this.getModuleNames = function () {
    /**:QBDI.prototype.getModuleNames()
      Use QBDI engine to retrieve loaded modules.
       :returns: list of module names (ex: ["ls", "libc", "libz"])
      :rtype: [String]
    */
    var sizePtr = Memory.alloc(4);
    var modsPtr = QBDI_C.getModuleNames(sizePtr);
    var size = Memory.readU32(sizePtr);

    if (modsPtr.isNull() || size === 0) {
      return [];
    }

    var mods = [];
    var p = modsPtr;

    for (var i = 0; i < size; i++) {
      var strPtr = Memory.readPointer(p);
      var str = Memory.readCString(strPtr);
      mods.push(str);
      System.free(strPtr);
      p = p.add(Process.pointerSize);
    }

    System.free(modsPtr);
    return mods;
  }; // Logs


  this.addLogFilter = function (tag, priority) {
    var tagPtr = Memory.allocUtf8String(tag);
    QBDI_C.addLogFilter(tagPtr, priority);
  }; // Helpers


  this.newInstCallback = function (cbk) {
    /**:QBDI.prototype.newInstCallback(cbk)
      Create a native **Instruction callback** from a JS function.
       :param cbk: an instruction callback (ex: function(vm, gpr, fpr, data) {};)
       :returns: an instruction callback
      :rtype: NativeCallback
       Example:
            >>> var icbk = vm.newInstCallback(function(vm, gpr, fpr, data) {
            >>>   inst = vm.getInstAnalysis();
            >>>   console.log("0x" + inst.address.toString(16) + " " + inst.disassembly);
            >>>   return VMAction.CONTINUE;
            >>> });
     */
    if (typeof cbk !== 'function' || cbk.length !== 4) {
      return undefined;
    } // Use a closure to provide object


    var vm = this;

    var jcbk = function (vmPtr, gprPtr, fprPtr, dataPtr) {
      var gpr = new GPRState(gprPtr);
      var fpr = new FPRState(fprPtr);
      var data = getUserData(dataPtr);
      return cbk(vm, gpr, fpr, data);
    };

    return new NativeCallback(jcbk, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
  };

  this.newVMCallback = function (cbk) {
    /**:QBDI.prototype.newVMCallback(cbk)
      Create a native **VM callback** from a JS function.
       :param cbk: a VM callback (ex: function(vm, state, gpr, fpr, data) {};)
       :returns: a VM callback
      :rtype: NativeCallback
       Example:
            >>> var vcbk = vm.newVMCallback(function(vm, evt, gpr, fpr, data) {
            >>>   if (evt.event & VMEvent.EXEC_TRANSFER_CALL) {
            >>>     console.warn("[!] External call to 0x" + evt.basicBlockStart.toString(16));
            >>>   }
            >>>   return VMAction.CONTINUE;
            >>> });
     */
    if (typeof cbk !== 'function' || cbk.length !== 5) {
      return undefined;
    } // Use a closure to provide object and a parsed event


    var vm = this;

    var jcbk = function (vmPtr, state, gprPtr, fprPtr, dataPtr) {
      var s = parseVMState(state);
      var gpr = new GPRState(gprPtr);
      var fpr = new FPRState(fprPtr);
      var data = getUserData(dataPtr);
      return cbk(vm, s, gpr, fpr, data);
    };

    return new NativeCallback(jcbk, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
  };

  this.call = function (address, args) {
    /**:QBDI.prototype.call(address[, args])
      Call a function by its address (or through a Frida ``NativePointer``).
       :param address: function address (or Frida ``NativePointer``).
      :param [args]: optional list of arguments
       Arguments can be provided, but their types need to be compatible
      with the ``.toRword()`` interface (like ``NativePointer`` or ``UInt64``).
       Example:
            >>> var vm = new QBDI();
            >>> var state = vm.getGPRState();
            >>> vm.allocateVirtualStack(state, 0x1000000);
            >>> var aFunction = Module.findExportByName(null, "Secret");
            >>> vm.addInstrumentedModuleFromAddr(aFunction);
            >>> vm.call(aFunction, [42]);
     */
    address = address.toRword();
    var fargs = formatVAArgs(args); // Use this weird construction to work around a bug in the duktape runtime

    var _call = function (a, b, c, d, e, f, g, h, i, j) {
      var retPtr = Memory.alloc(Process.pointerSize);
      var res = QBDI_C.call(vm, retPtr, address, fargs[0], a, b, c, d, e, f, g, h, i, j);

      if (res == false) {
        throw new EvalError('Execution failed');
      }

      return ptr(Memory.readRword(retPtr));
    };

    return _call.apply(null, fargs[1]);
  };
  /**:QBDI.version
   QBDI version (major, minor, patch).
    {string:String,integer:Number,major:Number,minor:Number,patch:Number}
  */


  Object.defineProperty(this, 'version', {
    enumerable: true,
    get: function () {
      if (!QBDI_C.getVersion) {
        return undefined;
      }

      var version = {};
      var versionPtr = Memory.alloc(4);
      var vStrPtr = QBDI_C.getVersion(versionPtr);
      var vInt = Memory.readU32(versionPtr);
      version.string = Memory.readCString(vStrPtr);
      version.integer = vInt;
      version.major = vInt >> 8 & 0xf;
      version.minor = vInt >> 4 & 0xf;
      version.patch = vInt & 0xf;
      Object.freeze(version);
      return version;
    }
  });
  initialize.call(this);
}

; // nodejs export

if (typeof module !== "undefined") {
  var exports = module.exports = {
    QBDI_LIB_FULLPATH: QBDI_LIB_FULLPATH,
    QBDI: QBDI,
    rword: rword,
    GPR_NAMES: GPR_NAMES,
    REG_RETURN: REG_RETURN,
    REG_PC: REG_PC,
    REG_SP: REG_SP,
    VMError: VMError,
    InstPosition: InstPosition,
    VMAction: VMAction,
    VMEvent: VMEvent,
    AnalysisType: AnalysisType,
    OperandType: OperandType,
    RegisterAccessType: RegisterAccessType,
    MemoryAccessType: MemoryAccessType,
    SyncDirection: SyncDirection,
    // Allow automagic exposure of QBDI interface in nodejs GLOBAL
    import: function () {
      for (var key in this) {
        if (key !== "import") {
          global[key] = this[key];
        }
      }
    }
  };
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],2:[function(require,module,exports){
const qbdi = require("./frida-qbdi");

qbdi.import();
rpc.exports = {
  init: function (name, entrypoint, imagebase) {
    init_qbdi(name, entrypoint, imagebase);
  }
};

function init_qbdi(name, entrypoint, imagebase) {
  var modules = Process.enumerateModulesSync();
  send({
    "type": "module_map",
    "modules": modules
  });
  var module_map = new ModuleMap();
  var vm = new QBDI();
  var state = vm.getGPRState();
  var stack = vm.allocateVirtualStack(state, 0x100000);
  vm.simulateCall(state, ptr(42).toRword());
  vm.addInstrumentedModule(name);
  var bb_callback = vm.newVMCallback(function (vm, evt, gpr, fpr, data) {
    send({
      "type": "coverage",
      "bb_start": evt.basicBlockStart,
      "bb_end": evt.basicBlockEnd,
      "path": module_map.find(ptr(evt.basicBlockStart)).path
    });
    VMAction.CONTINUE;
  });
  vm.addVMEventCB(VMEvent.BASIC_BLOCK_NEW, bb_callback, null);
  var process_base = Process.findModuleByName(name).base;
  var address_offset = process_base.sub(imagebase).toInt32();
  var actual_entrypoint = entrypoint + address_offset;
  vm.run(ptr(actual_entrypoint), ptr(42));
  send({
    "type": "done"
  });
}

},{"./frida-qbdi":1}]},{},[2])
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3Vzci9sb2NhbC9saWIvbm9kZV9tb2R1bGVzL2ZyaWRhLWNvbXBpbGUvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImpzL2ZyaWRhLXFiZGkuanMiLCJqcy9xY292LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOztBQ0FBOzs7Ozs7Ozs7Ozs7Ozs7OztBQWlCQTtBQUVBOzs7Ozs7QUFLQSxJQUFJLFVBQVUsR0FBRyxDQUFqQjtBQUNBLElBQUksVUFBVSxHQUFHLENBQWpCO0FBQ0EsSUFBSSxVQUFVLEdBQUcsQ0FBakI7QUFDQSxJQUFJLG9CQUFvQixHQUFJLFVBQVUsSUFBSSxDQUFmLEdBQXFCLFVBQVUsSUFBSSxDQUFuQyxHQUF3QyxVQUFuRTtBQUNBOzs7O0FBSUEsSUFBSSxPQUFPLE9BQVAsS0FBbUIsUUFBdkIsRUFBaUM7QUFDN0I7QUFDQSxNQUFJLE9BQU8sQ0FBQyxRQUFSLEtBQXFCLFFBQXJCLElBQWlDLE9BQU8sQ0FBQyxJQUFSLENBQWEsT0FBYixDQUFxQixLQUFyQixNQUFnQyxDQUFyRSxFQUF3RTtBQUNwRSxJQUFBLE9BQU8sQ0FBQyxJQUFSLENBQWEsc0RBQWI7QUFDQSxJQUFBLE9BQU8sQ0FBQyxJQUFSLENBQWEsaURBQWI7QUFDSDtBQUNKLEMsQ0FFRDtBQUNBOzs7QUFDQSxTQUFTLE1BQVQsR0FBa0I7QUFDZCxPQUFLLFdBQUwsR0FBbUIsVUFBUyxHQUFULEVBQWMsS0FBZCxFQUFxQjtBQUNwQyxRQUFJLEdBQUcsS0FBSyxTQUFaLEVBQXVCO0FBQ25CLGFBQU8sU0FBUDtBQUNIOztBQUNELFFBQUksS0FBSyxHQUFHLFNBQVo7O0FBQ0EsUUFBSSxLQUFLLEtBQUssU0FBZCxFQUF5QjtBQUNyQixVQUFJLEdBQUcsR0FBRyxLQUFLLENBQUMsTUFBaEI7QUFDQSxVQUFJLEtBQUssR0FBRyxLQUFaLENBRnFCLENBR3JCOztBQUNBLFdBQUssSUFBSSxDQUFDLEdBQUcsQ0FBYixFQUFn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
