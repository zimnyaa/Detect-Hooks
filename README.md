# Detect-Hooks

This is a fork of the `detect-hooks` BOF, rebuilt for sliver.

Also, there's a new BOF, `hooks-kernel`, that uses opcode comparisons instead of syscall stub signatures to find hooks in `kernelbase`/`kernel32`.

# sliver BOF porting notes

trustedsec/COFFLoader does not load any functions from windows.h, so frequent LoadLibrary calls in BOFs have to be replaced with `KERNEL32$LoadLibraryA`.

Aside from this, the BOFs are just built as: 
```
x86_64-w64-mingw32-gcc -c detect-hooks.c -o detect-hooks-mingw64-ll.o
i686-w64-mingw32-gcc -c detect-hooks.c -o detect-hooks-mingw32-ll.o
```

Load this with `extensions load`&`extensions install`.
