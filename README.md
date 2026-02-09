# LyticEnzyme

Breakdown of GraalVM's SubstrateVM towards analysis of Native Image (AOT) binaries

- [x] Closed type world support
- [x] Open type world support
- [ ] Relative code pointers (code base) support
- [x] Extract type information from `java.lang.Class` objects
  - [x] Native hosted method naming (partial)
  - [ ] Structure superclasses and inheritance
- [x] String recognizer and data renderer
- [x] Heap analyser
- [x] Function call convention fixup
  - [x] SysV, Win64 on x86
  - [x] AArch64
  - [x] RISC-V
  - [x] Thread register to `graal_isolatethread_t`
  - [ ] Code base register
- [ ] Class flags and modifiers
- [ ] Continuable analysis