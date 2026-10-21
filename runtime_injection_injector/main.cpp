#include <iostream>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <cstring>
#include <vector>
#include <unistd.h>

#include "util/query_pid.h"

// STAGE 0: helper to emit a 64-bit immediate into a register (x0-x30)
static void emitMov64(std::vector<uint32_t>& code, int reg, uint64_t val) {
    code.push_back(0xD2800000 | reg | ((val & 0xFFFF) << 5)); // MOVZ reg, (val & 0xFFFF)
    code.push_back(0xF2A00000 | reg | (((val >> 16) & 0xFFFF) << 5)); // MOVK reg, ((val >> 16) & 0xFFFF)
    code.push_back(0xF2C00000 | reg | (((val >> 32) & 0xFFFF) << 5)); // MOVK reg, ((val >> 32) & 0xFFFF)
    code.push_back(0xF2E00000 | reg | (((val >> 48) & 0xFFFF) << 5)); // MOVK reg, ((val >> 48) & 0xFFFF)
}

// STAGE 2: payload shellcode — runs in a pthread, calls dlopen(path, RTLD_NOW), stores result
static std::vector<uint32_t> buildPayloadShellcode(uint64_t dlopenAddr,
                                                    uint64_t resultAddr) {
    std::vector<uint32_t> code;

    // x0 = path (already set by bootstrap thread)
    emitMov64(code, 1, 2);            // x1 = RTLD_NOW
    emitMov64(code, 9, dlopenAddr);   // x9 = dlopen
    code.push_back(0xD63F0120);       // BLR x9  — call dlopen(path, RTLD_NOW)

    // x0 now holds dlopen's return value (NULL = failure, non-null = handle)
    // Store it so the injector can read it back via mach_vm_read_overwrite
    emitMov64(code, 10, resultAddr);  // x10 = result scratch address
    code.push_back(0xF9000140);       // STR x0, [x10]  (0xF9000140 = STR X0,[X10,#0])

    code.push_back(0x14000000);       // B . (park forever)
    return code;
}

// STAGE 1: raw Mach thread — bootstraps a real pthread to run stage 2.
static std::vector<uint32_t> buildBootstrapShellcode(uint64_t outPtrAddr, uint64_t payloadAddr, uint64_t pathAddr, uint64_t pthreadCreateAddr) {
    std::vector<uint32_t> code;

    emitMov64(code, 0, outPtrAddr);        // x0 = &pthread_t out
    emitMov64(code, 1, 0);                 // x1 = attr (NULL)
    emitMov64(code, 2, payloadAddr);       // x2 = start_routine (stage 2)
    emitMov64(code, 3, pathAddr);          // x3 = arg (path, becomes x0 in stage 2)
    emitMov64(code, 9, pthreadCreateAddr); // x9 = pthread_create_from_mach_thread
    code.push_back(0xD63F0120);            // BLR x9
    code.push_back(0x14000000);            // B . (park forever)

    return code;
}

int main() {
    
    // Print the current process ID for reference
    std::cout << "current PID: " << getpid() << std::endl;

    // Find the PID of the target process by its name
    std::string target = "runtime_injection_target";
    pid_t pid = findPidByName(target);

    // Check if the target process was found and handle the case where it wasn't
    if (pid == -1) {
        std::cout << "target not found" << std::endl;
        return -1;
    }

    // Print the PID of the target process for confirmation
    std::cout << "target PID: " << pid << std::endl;

    // Obtain the task port for the target process using its PID
    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);

    // Check if obtaining the task port was successful and handle any errors
    if (kr != KERN_SUCCESS) {
        std::cout << "task_for_pid failed: " << mach_error_string(kr) << std::endl;
        return -1;
    }

    // Define the path to the dynamic library (dylib) that will be injected into the target process
    const char* dylibPath = "/Users/dmitri/Documents/working/macho-runtime-injection/runtime_injection_injector/payload/payload.dylib";
    size_t pathLen = strlen(dylibPath) + 1; // Include null terminator in length

    // Allocate memory in the target process for the dylib path and write the path into that memory
    mach_vm_address_t remotePathAddr = 0;
    kr = mach_vm_allocate(task, &remotePathAddr, pathLen, VM_FLAGS_ANYWHERE); // Allocate memory in the target process for the dylib path

    // Check if the allocation was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "allocate path failed\n"; 
        return -1; 
    }

    // Write the dylib path into the allocated memory in the target process
    kr = mach_vm_write(task, remotePathAddr, (vm_offset_t)dylibPath, (mach_msg_type_number_t)pathLen);

    // Check if writing the path was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "write path failed\n"; 
        return -1; 
    }

    // Resolve the addresses of dlopen and pthread_create_from_mach_thread in the local process to use them in the target process
    void* localDlopenAddr = (void*)dlopen; // Get the address of dlopen in the local process
    void* localPthreadCreateAddr = dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"); // Get the address of pthread_create_from_mach_thread in the local process

    // Check if the addresses were resolved successfully and handle any errors
    if (!localPthreadCreateAddr) {
        std::cout << "couldn't resolve pthread_create_from_mach_thread" << std::endl;
        return -1;
    }

    // Print the resolved addresses of dlopen and pthread_create_from_mach_thread for debugging purposes
    std::cout << "dlopen addr:              0x" << std::hex << (uint64_t)localDlopenAddr << std::endl;
    std::cout << "pthread_create_from_mach: 0x" << std::hex << (uint64_t)localPthreadCreateAddr << std::endl;

    // Allocate memory in the target process for a scratch space and a place to store the result of dlopen
    mach_vm_address_t remoteScratchAddr = 0;
    kr = mach_vm_allocate(task, &remoteScratchAddr, 16, VM_FLAGS_ANYWHERE); // Allocate 16 bytes for scratch space in the target process

    // Check if the allocation was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "allocate scratch failed\n"; 
        return -1; 
    }

    // Define the address in the target process where the result of dlopen will be stored (8 bytes after the scratch space)
    mach_vm_address_t remoteDlopenResultAddr = remoteScratchAddr + 8;

    // Build the payload shellcode that will be injected into the target process, which will call dlopen with the provided path and store the result
    auto payloadCode = buildPayloadShellcode((uint64_t)localDlopenAddr, remoteDlopenResultAddr);
    size_t payloadSize = payloadCode.size() * sizeof(uint32_t); // Calculate the size of the payload shellcode in bytes

    // Allocate memory in the target process for the payload shellcode and the bootstrap shellcode
    mach_vm_address_t remoteCodeAddr = 0;
    size_t totalCodeSize = 4096; // Allocate a full page (4096 bytes) for the code to ensure enough space for both payload and bootstrap shellcode
    kr = mach_vm_allocate(task, &remoteCodeAddr, totalCodeSize, VM_FLAGS_ANYWHERE); // Allocate memory in the target process for the code (payload + bootstrap)

    // Check if the allocation was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "allocate code failed\n"; 
        return -1; 
    }

    // Calculate the addresses for the payload and bootstrap shellcode within the allocated code space in the target process
    mach_vm_address_t payloadAddr    = remoteCodeAddr; // Payload shellcode will be placed at the start of the allocated code space
    mach_vm_address_t bootstrapAddr  = payloadAddr + ((payloadSize + 3) & ~size_t(3)); // Bootstrap shellcode will be placed immediately after the payload shellcode, aligned to a 4-byte boundary

    // Build the bootstrap shellcode that will create a new pthread in the target process to run the payload shellcode
    auto bootstrapCode = buildBootstrapShellcode(remoteScratchAddr, payloadAddr, remotePathAddr, (uint64_t)localPthreadCreateAddr);
    size_t bootstrapSize = bootstrapCode.size() * sizeof(uint32_t);

    // Check if the combined size of the payload and bootstrap shellcode exceeds the allocated code space in the target process
    if (bootstrapAddr + bootstrapSize > remoteCodeAddr + totalCodeSize) {
        std::cout << "shellcode overflows page\n"; return -1;
    }

    // Write the payload shellcode into the allocated code space in the target process
    kr = mach_vm_write(task, payloadAddr,   (vm_offset_t)payloadCode.data(),   (mach_msg_type_number_t)payloadSize);

    // Check if writing the payload shellcode was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "write payload failed\n"; 
        return -1; 
    }

    // Write the bootstrap shellcode into the allocated code space in the target process
    kr = mach_vm_write(task, bootstrapAddr, (vm_offset_t)bootstrapCode.data(), (mach_msg_type_number_t)bootstrapSize);

    // Check if writing the bootstrap shellcode was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "write bootstrap failed\n"; 
        return -1; 
    }

    // Set the memory protection of the allocated code space in the target process to be readable and executable, allowing the injected shellcode to run
    kr = mach_vm_protect(task, remoteCodeAddr, totalCodeSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    // Check if setting the memory protection was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "protect code failed\n"; 
        return -1; 
    }

    // Allocate a stack for the new thread that will run the bootstrap shellcode in the target process
    mach_vm_address_t remoteStackAddr = 0; // Address of the allocated stack in the target process
    size_t stackSize = 512 * 1024; // Allocate 512 KB for the stack of the new thread

    // Allocate memory for the stack in the target process
    kr = mach_vm_allocate(task, &remoteStackAddr, stackSize, VM_FLAGS_ANYWHERE);

    // Check if the stack allocation was successful and handle any errors
    if (kr != KERN_SUCCESS) {  
        std::cout << "allocate stack failed\n"; 
        return -1; 
    }

    // Set the memory protection of the allocated stack in the target process to be readable and writable, allowing the new thread to use it as its stack
    kr = mach_vm_protect(task, remoteStackAddr, stackSize, FALSE, VM_PROT_READ | VM_PROT_WRITE);

    // Check if setting the memory protection for the stack was successful and handle any errors
    if (kr != KERN_SUCCESS) { 
        std::cout << "protect stack failed\n"; 
        return -1; 
    }

    // Calculate the top of the stack for the new thread, ensuring it is aligned to a 16-byte boundary as required by the ARM64 architecture
    mach_vm_address_t stackTop = (remoteStackAddr + stackSize) & ~0xFULL;

    // Set up the initial thread state for the new thread that will run the bootstrap shellcode in the target process. This includes setting the program counter (PC) to the address of the bootstrap shellcode and the stack pointer (SP) to the top of the allocated stack.
    arm_thread_state64_t threadState = {0};
    threadState.__pc = bootstrapAddr;
    threadState.__sp = stackTop;

    // Create a new thread in the target process that will run the bootstrap shellcode, which in turn will create a pthread to run the payload shellcode. The new thread is created in a running state with the specified initial thread state.
    thread_act_t remoteThread;
    kr = thread_create_running(task, ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&threadState), ARM_THREAD_STATE64_COUNT, &remoteThread);

    // Check if creating the new thread was successful and handle any errors
    if (kr != KERN_SUCCESS) {
        std::cout << "thread_create_running failed: " << mach_error_string(kr) << std::endl;
        return -1;
    }

    // Wait for a short period to allow the payload thread to run and execute the injected code in the target process. This is necessary because the injector needs to read back the result of dlopen from the target process after it has been executed.
    std::cout << "waiting for payload thread to run..." << std::endl;
    usleep(500000);

    // Read back the result of dlopen from the target process to determine if the dynamic library was successfully loaded. The result is stored in the allocated scratch space in the target process, and the injector reads it back using mach_vm_read_overwrite.
    uint64_t dlopenResult = 0;
    mach_vm_size_t outSize = 0;

    kr = mach_vm_read_overwrite(task, remoteDlopenResultAddr, sizeof(dlopenResult), (mach_vm_address_t)&dlopenResult, &outSize);

    // Check if reading the result was successful and handle any errors
    if (kr != KERN_SUCCESS) {
        std::cout << "read result failed: " << mach_error_string(kr) << std::endl;
        return -1;
    }

    
    if (dlopenResult == 0) {
        std::cout << "dlopen returned NULL — dylib failed to load." << std::endl;
        std::cout << "Check: correct path? arm64 slice? codesigned? (`file payload.dylib`, `codesign -s - payload.dylib`)" << std::endl;
    } 
    else {
        std::cout << "dlopen succeeded (handle: 0x" << std::hex << dlopenResult << ")" << std::endl;
        std::cout << "constructor should have fired — check target stdout" << std::endl;
    }

    return 0;
}