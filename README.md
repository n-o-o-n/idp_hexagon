Hexagon Processor Module
========================
This is [Hexagon](https://developer.qualcomm.com/software/hexagon-dsp-sdk/dsp-processor) (aka QDSP6) processor module for  [IDA Pro](https://www.hex-rays.com/products/ida/) disassembler.
Features:
 * Supports all Hexagon versions: V4, V5, V55, V60, V61, V62, V65, V66, V67, V67t, V68
 * Supports Hexagon Vector Extensions (HVX), audio extensions
 * Supports Hexagon Matrix Extensions (HMX), V66 NN extensions
 * Supports all known instructions
 * Supports ELF relocations (both static and dynamic)
 * Supports IDA v7.0-7.5

Information on instructions was mainly gathered from [LLVM](https://github.com/llvm/llvm-project/blob/master/llvm/lib/Target/Hexagon/HexagonDepInstrInfo.td), whereas missing system-level instructions were taken from Programmer's Reference Manual.


Compilation
-----------
You will need the target IDA SDK ([7.0](https://www.hex-rays.com/products/ida/support/ida/idasdk70.zip), [7.2](https://www.hex-rays.com/products/ida/support/ida/idasdk72.zip), [7.3](https://www.hex-rays.com/products/ida/support/ida/idasdk73.zip), [7.5](https://www.hex-rays.com/products/ida/support/ida/idasdk75.zip)) (password protected).  
You will also need a C++17 compiler, like Visual Studio 2015/2017, or any recent GCC or Clang.

Install target IDA SDK, copy `hexagon` folder into $SDK/module folder, and modify $SDK/module/makefile to include hexagon in `ALLDIRS`.  
Build SDK, the resulting binary will be in $SDK/bin/procs/hexagon.dll.


Binary download
---------------
Binaries for Windows can be found under [releases](https://github.com/n-o-o-n/idp_hexagon/releases).


Installation
------------
Copy the hexagon.dll file to the procs subdirectory of your IDA installation.


Usage
-----
Start IDA, load binary and select 'Qualcomm Hexagon DSP [QDSP6]' from the processor type.
In case of ELF binary just press the "Set" button.  
Otherwise IDA would still sucessfully load binary, but will complain about unknown relocations.


Issues
------
 * In case of mixed code and data the former may have incorrect packet boundaries.
 * Some rare relocation types are not properly recognized.
 * Does not distinguish between different Hexagon versions; will disassemble instructions not supported by a particular version.
 * IDA stores flags for two operands only, and all subsequent operands will have the same flag. For example, if the 2nd operand is an offset, then 4th will be treated as offset too.
 * Xref to a stack variable fails; IDA checks if an instruction modifies operand by reading from processor_t::instruc (which is NULL).


Other Hexagon Processor modules
===============================
 * [hexagon](https://github.com/gsmk/hexagon)
 * [nogaxeh](https://github.com/ANSSI-FR/nogaxeh)
 * [hexag00n](https://github.com/programa-stic/hexag00n)


Author
=======
n-o-o-n (n_o_o_n@bk.ru)


License
-------
LGPLv3. For more information see [LICENSE](./LICENSE).


History
-------
2020-06-29 version 1.0  
2020-06-30 added support for FP-based stack vars  
2020-07-01 added basic support for type information; fixed warning message in IDA 7.2 ("Bad declaration..."); symbol, string and relocation tables are now shown for .so binaries  
2020-07-02 added function arguments locations  
2020-07-10 trace SP modification at the end of a packet  
2020-07-13 added automatic comments for function arguments  
2020-07-16 added switch support; version 2.0 released  
2021-02-04 added support for IDA v7.3 and v7.5  
2021-02-26 added support for Hexagon v68  
2021-03-02 fixed analysis order; version 3.0 released  
2021-06-25 fixed crashes related to missing segment registers  
