use std::arch::asm;
use std::env;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;
use windows::core::imp::{GetProcAddress};
use windows::core::PCSTR;
use windows::Win32::Foundation::{FALSE, HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::System::Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS};

fn main() {

    // top-level exception filter to catch any exceptions
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
    unsafe {
        SetUnhandledExceptionFilter(Some(exception_filter));
    }

    // get pid from first positional argument
    let pid = cli_pid();

    // demonstrate opening process via the pid
    // open_process_api(pid);

    // call NtOpenProcess via System Service Number
    let ssn = get_ssn(PCSTR("NtOpenProcess\0".as_ptr()));
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

/// Make a call to OpenProcess via the ordinary Windows API
fn open_process_api(pid: u32) {
    let res = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
    };

    if res.is_ok() {
        println!("[+] Handle obtained, value: {:?}", res.unwrap());
    } else {
        println!("[-] Unable to get handle. Error: {:?}", res)
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

    // read the syscall number from the functions address
    let nt_function_address = nt_function_address.unwrap() as *const u8;
    let nt_function_ssn = unsafe { *(nt_function_address.add(4) as *const u32) };

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