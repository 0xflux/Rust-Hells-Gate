# EDR evasion in Rust with Direct Syscalls

# About

This is a proof of concept for calling syscalls directly via Rust for EDR evasion, by calling direct into the
Windows kernel instead of using the normal Windows API. This is well implemented in C, but I could not find
any references to an implementation in Rust - so hopefully this showcases that.

[Blog post](https://fluxsec.red) & [YouTube](https://www.youtube.com/@FluxSec) video incoming!

# Background

EDR Hooking refers to the methods used by Endpoint Detection and Response (EDR) systems to monitor the behavior 
of software on a computer, particularly for identifying and mitigating potential threats. These systems are 
designed to detect malicious activities by observing interactions between software processes and the operating 
system.

There are different ways in which EDR’s will perform hooking, a few of the more common:

## Inline Hooking:

I have written a blog post about this technique, as inspired by many devs in this space, but none more than
Cr0w [website](https://www.crow.rip/crows-nest), 
[Twitter](https://x.com/cr0ww_), 
[here](https://fluxsec.red/dll-injection-edr-evasion-1). <3 big love if you read this.

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