use std::arch::asm;
use std::os::windows::ffi::OsStringExt;
use std::{env, slice};
use std::ffi::{c_void, CStr, OsString};
use std::mem::size_of;
use std::ptr::null_mut;
use str_crypter::{sc, decrypt_string};
use windows::core::imp::GetProcAddress;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::Kernel::LIST_ENTRY;
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE};
use windows::Win32::System::Threading::{PEB, PEB_LDR_DATA, PROCESS_ALL_ACCESS};
use windows::Win32::System::Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS, IMAGE_NT_HEADERS64};
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

fn main() {

    // top-level exception filter to catch any exceptions
    // https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
    unsafe {
        SetUnhandledExceptionFilter(Some(exception_filter));
    }

    // get pid from first positional argument
    let pid = cli_pid();

    // read iat
    read_iat();

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

// Read from IAT for Hell's Gate technique 

/// Return a pointer to the PEB
unsafe fn get_peb_ptr() -> *const PEB {
    let peb: *const PEB;
    // access the peb directly via the GS register
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
    );

    peb
}

fn read_iat() {
    // get peb via GS register
    let peb: *const PEB = unsafe { get_peb_ptr() };

    unsafe {
        // get the loader data section
        let loader_section = (*peb).Ldr; // points to NTDLL where the PEB_LDR_DATA exists, containing initialised data.
        println!("Loader section address: {:p}", loader_section);

         // Verify the loader section
         let loader_section = &*(loader_section as *const PEB_LDR_DATA);
         println!("InMemoryOrderModuleList: {:p}", loader_section.InMemoryOrderModuleList.Flink);
        
        // get the header of the module list, accessed via the Flink (aka the next link in the doubly linked list)
        // let module_list = (*loader_section).InMemoryOrderModuleList.Flink; // points to the heap

        let module_list = loader_section.InMemoryOrderModuleList.Flink;
        println!("Module list header address: {:p}", module_list);

        let mut current_entry: *mut LIST_ENTRY = module_list;
        println!("Current entry address: {:p}", current_entry);

        println!();
        println!();

        // iterate the linked list, this will exit once we have returned to the head of the linked list.
        // we need to change our immutable pointer to a mutable one
        while current_entry != &(*loader_section).InMemoryOrderModuleList as *const _ as *mut _ {

            println!("Current entry: {:p}", current_entry);

            // Verify current entry content
            let ldr_entry = &*(current_entry as *mut LDR_DATA_TABLE_ENTRY);
            println!("LDR entry DllBase: {:p}", ldr_entry.DllBase);
            // Print FullDllName
            let full_dll_name = &ldr_entry.FullDllName;
            let dll_name = read_wide_string(full_dll_name.Buffer.0, full_dll_name.Length as usize);
            println!("LDR entry FullDllName: {}", dll_name);

            // Dump details to verify against x64dbg
            println!("Flink: {:p}, Blink: {:p}", (*current_entry).Flink, (*current_entry).Blink);

            let mut base_address: *mut c_void = ldr_entry.DllBase;

            println!("Base address: {:p}", base_address);


            println!("Base address after adjustment: {:p}", base_address);

            // Verify the memory content at the base address before reading the DOS header
            if base_address.is_null() || (base_address as usize) < 0x10000 {
                println!("Invalid DllBase address: {:p}", base_address);
                current_entry = (*current_entry).Flink;
                continue;
            }

            let dos_header: IMAGE_DOS_HEADER = read_memory(base_address as *const IMAGE_DOS_HEADER);
            println!("DOS header e_magic: {:#X}", dos_header.e_magic);

            if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
                println!("Invalid DOS signature: {:#X}", dos_header.e_magic);
                current_entry = (*current_entry).Flink;
                continue;
            }

            println!("Hello 2?");

            // now read NT headers
            let nt_header: IMAGE_NT_HEADERS64 = read_memory(base_address.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
            if nt_header.Signature != IMAGE_NT_SIGNATURE {
                current_entry = (*current_entry).Flink;
                continue;
            }

            // locate the import directory
            // optional header contains information about the PE, including size and location of tables
            // DataDirectory is an array of IMAGE_DATA_DIRECTORY structs, each entry points to different data directories
            // DataDirectory[1] is the IAT
            // The VirtualAddress field is the RVA (relative to the base addr of the module) of the Import Directory, which we can then convert
            // https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
            let import_dir_rva = nt_header.OptionalHeader.DataDirectory[1].VirtualAddress;
            if import_dir_rva == 0 {
                current_entry = (*current_entry).Flink;
                continue;
            }

            // convert RVA to VA
            let import_dir_addr = base_address.offset(import_dir_rva as isize) as *const IMAGE_IMPORT_DESCRIPTOR;

            // read and print the import descriptors
            let mut import_descriptor = read_memory(import_dir_addr);
            while import_descriptor.Name != 0 {
                let name_address = base_address.offset(import_descriptor.Name as isize);
                let dll_name = CStr::from_ptr(name_address as *const i8).to_str().unwrap_or("Unknown");
                println!("DLL: {}", dll_name);

                // read thunk data
                let mut thunk_address = base_address.offset(import_descriptor.FirstThunk as isize) as *const usize;
                while read_memory(thunk_address) != 0 {
                    let thunk_data: usize = read_memory(thunk_address);
                    let func_name_address = base_address.offset(thunk_data as isize + 2) as *const i8; // skip hint 2 bytes
                    let func_name = CStr::from_ptr(func_name_address).to_str().unwrap_or("Unknown");
                    println!("Function: {}", func_name);

                    thunk_address = thunk_address.offset(1);
                }

                import_descriptor = read_memory(import_dir_addr.offset(1))
            }

            current_entry = (*current_entry).Flink;
        }
    }
    
}

unsafe fn read_memory<T>(address: *const T) -> T {
    std::ptr::read(address)
}

unsafe fn get_image_base(entry: *mut LIST_ENTRY) -> *const u8 {
    // Cast the LIST_ENTRY to LDR_DATA_TABLE_ENTRY to access the DllBase field
    let ldr_entry = entry as *mut LDR_DATA_TABLE_ENTRY;
    (*ldr_entry).DllBase as *const u8
}

unsafe fn read_wide_string(buffer: *const u16, length: usize) -> String {
    let slice = slice::from_raw_parts(buffer, length / 2); // length is in bytes, convert to number of u16
    let os_string = OsString::from_wide(slice);
    os_string.to_string_lossy().into_owned()
}

fn find_module_base(peb: *const PEB, module_name: &str) -> Option<*mut u8> {
    unsafe {
        let loader_section = (*peb).Ldr;
        let loader_section = &*(loader_section as *const PEB_LDR_DATA);
        let mut current_entry: *mut LIST_ENTRY = loader_section.InMemoryOrderModuleList.Flink;

        while current_entry != &loader_section.InMemoryOrderModuleList as *const _ as *mut _ {
            let ldr_entry = &*(current_entry as *mut LDR_DATA_TABLE_ENTRY);
            let full_dll_name = &ldr_entry.FullDllName;
            let dll_name = read_wide_string(full_dll_name.Buffer.0, full_dll_name.Length as usize);

            if dll_name.to_lowercase() == module_name.to_lowercase() {
                return Some(ldr_entry.DllBase as *mut u8);
            }

            current_entry = (*current_entry).Flink;
        }
    }
    None
}
