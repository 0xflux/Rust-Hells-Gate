# Hells Gate EDR evasion in Rust with Direct Syscalls

<img width="1222" alt="image" src="https://github.com/0xflux/Rust-syscall-EDR-evasion/assets/49762827/b8a788fe-aeec-46b2-bce3-c12d98a2a01a">

# About

This POC demonstrates a call down into NtOpenProcess via Hell's Gate (EDR Evasion, implemented in Rust); for this to be a fully functional malware loader there are
a few other API calls that you must rebuild as syscalls, so this just demonstrates the technique as a POC.

Check my [blog post at fluxsec.red](https://fluxsec.red/rust-edr-evasion-hells-gate) for this technique! Also I have published
a YouTube video on this where we dive deep into the topic 
[https://www.youtube.com/watch?v=aw6QO4ZDg_U](https://www.youtube.com/watch?v=aw6QO4ZDg_U)

If you like this, 
please subscribe to my [Twitter](https://twitter.com/0xfluxsec) and [YouTube](https://www.youtube.com/@FluxSec) 
it would really help me! Feel free to reach out to me on Twitter also, would be great to connect!

# Background

Hell’s Gate is a technique published by VX Underground devs. The original paper can be found here. Hell’s Gate is a technique that is now a good few years old, which was a solid attempt at EDR Evasion. Fast forward a few years to today, many EDR’s will now combat this technique - nevertheless it is still great to learn from. I’m working on my own EDR Evasion technique called Lucifers Path, which in theory should work against current EDR’s - but more on that in the future.

Whilst Hell’s Gate may still work on some EDR’s, it does work against antivirus such as Windows Defender, and another premium, paid for, AV I have tested this against.

Hel;l’s Gate works in two parts, the first, as stated above I have covered in my blog post on direct syscalls in C. The second part of Hell’s Gate is where it differs from the technique used in that post. In that post we resolve function pointers to ntdll.dll functions by making use of the Windows API’s GetProcAddress and LoadLibraryA - both of which could flag a risk score with AntiVirus or EDR. Hell’s Gate instead resolves the function pointer to the ntdll.dll functions by accessing the PEB (Process Environment Block) in order to resolve the base address of the module we are interested in (in this case ntdll.dll); and then parsing this DLL for the Export Address Table and iterating through it looking for the function we wish to get the address of.

This technique tries to bypass EDR hooking, which is used to inspect what a piece of code is doing at runtime. For example, EDR or antivirus software may detect activities such as opening handles to other processes, injecting memory remotely, and adding shellcode. This sequence of events can be easily hooked and monitored via certain Windows DLL APIs. By using Hell’s Gate to avoid these hooks, we can prevent this behavior analysis from happening, thus evading detection by EDR solutions. Modern EDR’s will now account for this technique, by hooking within NTDLL itself, and overwriting the SSN, so we cannot read it.

Take a look at the diagram which follows this list of the Hell's Gate process which is hopefully a little easier to digest...

1) First we get the address of the `PEB` (Process Environment Block)
2) Within the `PEB` is a pointer to a `PEB_LDR_DATA` structure
3) Within `PEB_LDR_DATA` is a pointer to InMemoryOrderModuleList
4) `InMemoryOrderModuleList` points to a `LDR_DATA_TABLE_ENTRY`, but specifically points to a `LIST_ENTRY` structure within the `LDR_DATA_TABLE_ENTRY`. `LDR_DATA_TABLE_ENTRY` is essentially a doubly linked list.
5) The `LIST_ENTRY` structure contains more pointers:
   1) `Flink` points to the next `LIST_ENTRY` within a LDR_DATA_TABLE_ENTRY
   2) `Blink` points to the previous `LIST_ENTRY` within a LDR_DATA_TABLE_ENTRY
6) Within each `LDR_DATA_TABLE_ENTRY`, there is a pointer to the `DLLBase`, the base address (virtual address) of the module the `LDR_DATA_TABLE_ENTRY` relates to.
7) We take that virtual address, which will contain a DLL mapped to memory, to then parse the `PE` (Portable Executable) headers
8) We search for the `DataDirectory` within the `OptionalHeader` of the `PE`
9) Within the `DataDirectory`, at index 0, is the `RVA` (Relative Virtual Address) of the `Export Address Table` (relative to the `DLLBase`)
10) The `Export Address Table` contains all of the functions the DLL exports; this is what we iterate through to find our function (such as `NtOpenProcess`)
11) Finally, we can get the ordinal number, and use it to obtain a pointer to the address where that exported function resides.

![hellsgate](https://github.com/0xflux/Rust-Hells-Gate/assets/49762827/c4a35cd5-24f6-4731-bff3-773bcd4a381d)

## Usage

```shell
./demo.exe <pid>

# or if running from source code:
cargo run -- <pid>
```

![image](https://github.com/0xflux/Rust-Hells-Gate/assets/49762827/f92f0011-fd54-4596-a3b2-6c9857a650ca)

### Proof:

Here's a side by side comparison of on the left making a call to OpenProcess via the Windows API 
(commented out in the source code normally), and on the right is the binary dump when using the Syscall technique.
As you can see, OpenProcess isn't listed!

![image](https://github.com/0xflux/Rust-syscall-EDR-evasion/assets/49762827/65f66427-4b06-4070-8a35-782de96ce81b)

# Legal disclaimer

This is simply a PROOF OF CONCEPT and is not enough for anybody to take away without a deep knowledge in this
field; it is script kiddy proof. 

This project, including all associated source code and documentation, is developed and shared solely for 
educational, research, and defensive purposes in the field of cybersecurity. It is intended to be used 
exclusively by cybersecurity professionals, researchers, and educators to enhance understanding, develop 
defensive strategies, and improve security postures.

Under no circumstances shall this project be used for criminal, unethical, or any other unauthorized activities. 
This is meant to serve as a resource for learning and should not be employed for offensive operations or actions 
that infringe upon any individual's or organization's rights or privacy.

The author of this project disclaims any responsibility for misuse or illegal application of the material 
provided herein. By accessing, studying, or using this project, you acknowledge and agree to use the information 
contained within strictly for lawful purposes and in a manner that is consistent with ethical guidelines and 
applicable laws and regulations.

USE AT YOUR OWN RISK. If you decide to use this software CONDUCT A THOROUGH INDEPENDENT CODE REVIEW to ensure it 
meets your standards. No unofficial third party dependencies are included to minimise attack surface of a supply 
chain risk. I cannot be held responsible for any problems that arise as a result of executing this, the burden 
is on the user of the software to validate its safety & integrity. All care has been taken to write safe code.

It is the user's responsibility to comply with all relevant local, state, national, and international laws and 
regulations related to cybersecurity and the use of such tools and information. If you are unsure about the 
legal implications of using or studying the material provided in this project, please consult with a legal 
professional before proceeding. Remember, responsible and ethical behavior is paramount in cybersecurity research 
and practice. The knowledge and tools shared in this project are provided in good faith to contribute positively 
to the cybersecurity community, and I trust they will be used with the utmost integrity.
