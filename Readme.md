# Hells Gate EDR evasion in Rust with Direct Syscalls

<img width="1222" alt="image" src="https://github.com/0xflux/Rust-syscall-EDR-evasion/assets/49762827/b8a788fe-aeec-46b2-bce3-c12d98a2a01a">

# About

This is a proof of concept for calling syscalls directly via Rust for EDR evasion, by calling direct into the
Windows kernel instead of using the normal Windows API. This is well implemented in C, but I could not find
any references to an implementation in Rust - so hopefully this showcases that.

This POC demonstrates a call down into NtOpenProcess; for this to be a fully functional malware loader there are
a few other API calls that you must rebuild as syscalls, so this just demonstrates the technique as a POC.

This technique is also referred to as Hells Gate, so this is a hells gate implementation
in Rust. Here is an excellent blog post about Hells Gate https://redops.at/en/blog/exploring-hells-gate.

Check my [blog post](https://fluxsec.red/rust-edr-evasion-hells-gate) for this technique! Also I have published
a YouTube video on this where we dive deep into the topic [https://www.youtube.com/@FluxSec](https://www.youtube.com/@FluxSec)

If you like this, 
please subscribe to my [Twitter](https://twitter.com/0xfluxsec) and [YouTube](https://www.youtube.com/@FluxSec) 
it would really help me!

## Usage

```shell
./demo.exe <pid>

# or if running from source code:
cargo run -- <pid>
```

![image](https://github.com/0xflux/Rust-syscall-EDR-evasion/assets/49762827/61137b3a-788e-4dcd-afee-6543dfa69aab)

### Proof:

Here's a side by side comparison of on the left making a call to OpenProcess via the Windows API 
(commented out in the source code normally), and on the right is the binary dump when using the Syscall technique.
As you can see, OpenProcess isn't listed!

![image](https://github.com/0xflux/Rust-syscall-EDR-evasion/assets/49762827/65f66427-4b06-4070-8a35-782de96ce81b)



# Background

EDR Hooking refers to the methods used by Endpoint Detection and Response (EDR) systems to monitor the behavior 
of software on a computer, particularly for identifying and mitigating potential threats. These systems are 
designed to detect malicious activities by observing interactions between software processes and the operating 
system.

There are different ways in which EDR’s will perform hooking, a few of the more common:

## Inline Hooking:

I have previously written a [blog post about this technique (in C++)](https://fluxsec.red/dll-injection-edr-evasion-1), as inspired by many devs in this space, but none more than
Cr0w [website](https://www.crow.rip/crows-nest), 
[Twitter](https://x.com/cr0ww_). <3 big love if you read this.

The EDR modifies the actual binary code of a function in memory. It typically replaces the first few bytes of 
the function with a jump to its own monitoring code. When the hooked function is called, execution is diverted 
to the EDR’s code first, allowing it to monitor or modify the behaviour of the function. Here is a great resource 
to read more about detecting inline hooking: 
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions.

## Import Address Table (IAT) Hooking:

IAT hooking involves modifying a program’s import table, which lists the API functions used by the program. 
This means when the program runs, instead of calling the actual API function, it calls the EDR’s monitoring 
function.

# Credit

Credit to Cr0w who provided the get_ssn function in C, I have ported it over to Rust :).

Also inspired by this wonderful blog: https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls

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
