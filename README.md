unarmed
=======

unarmed is a plain C adaptation of Paul Guyot's ARM disassembler from the Einstein project

Summary
-------

Paul Guyot wrote an ARM disassembler as part of the [Einstein](http://code.google.com/p/einstein/) project.

I simply took this existing code, and converted it to plain C and made it compilable without any other dependencies.  I also did a little reformatting of the code to match my personal style so I could follow it a little better.  Lastly, the format of the output is slightly tweaked.

All the hard stuff was done by Paul.  This is simply a minor tweak of his work.

Compatibility
-------------

Einstein emulates a Newton, which uses a StrongARM-110 (armv4 instruction set).  This disassembler was intended for inspecting the Newton ROM.  I do not know if it is suitable for any other purposes or other variants of ARM.
