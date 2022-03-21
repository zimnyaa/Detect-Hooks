# Detect-Hooks

This is a fork of the `detect-hooks` BOF, rebuilt for sliver.

# sliver BOF porting notes

trustedsec/COFFLoader does not load any functions from windows.h, so frequent LoadLibrary calls in BOFs have to be replaced with `KERNEL32$LoadLibraryA`.

Aside from this, the BOFs are just built as: 
```
x86_64-w64-mingw32-gcc -c detect-hooks.c -o detect-hooks-mingw64-ll.o
i686-w64-mingw32-gcc -c detect-hooks.c -o detect-hooks-mingw32-ll.o
```

Load this with `extensions load`&`extensions install`.
