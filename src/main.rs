use std::arch::asm;
use std::os::windows::ffi::OsStringExt;
use std::slice::from_raw_parts;
use std::{env, panic};
use std::ffi::{c_void, OsString};
use std::mem::size_of;
use std::ptr::null_mut;
use str_crypter::{sc, decrypt_string};
use windows::core::imp::GetProcAddress;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use windows::Win32::System::Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS};

fn main() {

    // top-level exception filter to catch any exceptions
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
    unsafe {
        SetUnhandledExceptionFilter(Some(exception_filter));
    }

    // get pid from first positional argument
    let pid = cli_pid();

    // get NTDLL base adddr
    let ntdll = match get_module_base_asm("ntdll.dll") {
        Some(a) => a,
        None => panic!("Unable to get address"),
    };

    // call NtOpenProcess via System Service Number
    let nt = match sc!("NtOpenProcess", 20) {
        Ok(s) => s,
        Err(e) => panic!("Error converting  string: {e}"),
    };
    let nt = nt.as_str();

    let ssn = get_ssn(PCSTR(nt.as_ptr()));
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
fn get_ssn(nt_function: PCSTR) -> Option<u32> {
    let ntdll = unsafe { LoadLibraryA(PCSTR(b"ntdll.dll\0".as_ptr())) };
    if ntdll.is_err() {
        println!("[-] Error getting handle to ntdll.dll");
        return None;
    }

    let nt_function_address = unsafe {GetProcAddress(ntdll.unwrap().0, nt_function.as_ptr())};
    if nt_function_address.is_none() {
        println!("[-] Error getting address of: {:?}", nt_function);
        return None;
    }

    // read the syscall number from the function's address
    let nt_function_address = nt_function_address.unwrap() as *const u8;
    let byte4 = unsafe { *nt_function_address.add(4) };
    let byte5 = unsafe { *nt_function_address.add(5) };
    
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
#[allow(unused_assignments)]
fn get_module_base_asm(module_name: &str) -> Option<usize>{
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

        // set the current entry to the head of the list
        current_entry = in_memory_order_module_list;
        
        // iterate the modules searching for 
        loop {
            let dll_base: usize;
            let dll_name_address: usize;
            let dll_length: u16;
            
            // resolve the name of the module
            asm!(
                "mov {dll_base}, [{current_entry} + 0x30]",
                "mov {dll_name_address}, [{current_entry} + 0x60]",
                "movzx {dll_length}, word ptr [{current_entry} + 0x58]", // movzx expands a byte or word to a full dword
                dll_base = out(reg) dll_base,
                dll_name_address = out(reg) dll_name_address,
                dll_length = out(reg) dll_length,
                current_entry = in(reg) current_entry,
            );

            // check if the module name address is valid and not zero
            if dll_name_address != 0 && dll_length > 0 {
                // read the module name from memory
                let dll_name_slice = from_raw_parts(dll_name_address as *const u16, (dll_length / 2) as usize);
                let dll_name = OsString::from_wide(dll_name_slice);

                println!("Module: {:?}", dll_name);

                // do we have a match on the module name?
                if dll_name.to_string_lossy().eq_ignore_ascii_case(module_name) {
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