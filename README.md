# Dynamic Library Injection

A macOS runtime code injection tool that uses Mach task APIs and hand-rolled ARM64 shellcode to inject dynamic libraries into live processes without modifying the target binary on disk.

---

### Process for injection

```
Injector process
    ↓
task_for_pid() → get Mach task port for target
    ↓
mach_vm_allocate() → carve out memory in target's address space
    ↓
mach_vm_write() → write ARM64 shellcode + dylib path string
    ↓
mach_vm_protect() → mark shellcode region RX
    ↓
thread_create_running() → start raw Mach thread at stage 1
 
Stage 1 (bootstrap — raw Mach thread):
    calls pthread_create_from_mach_thread() → spawns real pthread
 
Stage 2 (payload — real pthread, TLS valid):
    calls dlopen(dylibPath, RTLD_NOW) → loads your dylib
    dylib constructor fires → your code runs inside the target
```

---

### Technologies:

<ul>
    <li>glm math library for both the injector and target</li>
    <li>GLFW and glew for the target</li>
    <li>cmake</li>
</ul>

---

### How to build:
1. For the injector:

```
cd runtime_injection_injector
cmake CMakeLists.txt
cmake --build .
sudo ./runtime_injection_injector
```

*Ensure to use <code>sudo</code> so all dyld functions can be used without crashing.

2. For the target:

```
cd runtime_injection_target
cmake CMakeLists.txt
cmake --build .
./runtime_injection_target
```

---

*Before running the injector, make sure the target is already running. Otherwise, there is no target to inject into.

---

### How to modify the payload

In the <code>runtime_injection_injector</code> directory, there is a <code>util/payload.cpp</code> file where you can manually modify the payload.

The payload should generally look like

```c++
#include <cstdio>
#include <dlfcn.h>
#include <unistd.h>
#include <vector>
#include <glm/glm.hpp>
#include <GLFW/glfw3.h>
#include <iostream>
#include <thread>

#include "structures.h"

// Any global variables here if needed

__attribute__((constructor))
static void injected() {
    printf("hello %d\n", getpid());

    std::thread([]() {

        // The names for the renderer and camera objects can be used with `nm target_name | grep <variable_name>`. Remove the first underscore from the name of the variable so the program can find it.

        // Attempt to find the renderer object in the target process using dlsym. The mangled name "renderer" corresponds to the global variable "renderer" in the target process.
        Renderer* renderer = reinterpret_cast<Renderer*>(dlsym(RTLD_MAIN_ONLY, "renderer"));


        Camera* camera = reinterpret_cast<Camera*>(dlsym(RTLD_MAIN_ONLY, "_ZN8Renderer6cameraE"));

        // Check if the renderer and camera objects were found successfully. If not, print an error message and return early.
        if (!renderer) {
            std::cout << "renderer not found" << std::endl;
            return;
        }
        if (!camera) {
            std::cout << "camera not found" << std::endl;
            return;
        }
        // Insert logic...

    }).detach();
}
```

There is a special <code>compile_to_dylib.sh</code> in the <code>runtime_injection_injector</code> directory.
```
sh runtime_injection_injector/compile_to_dylib.sh
```
After running, the payload will be compiled to a dynamic library (.dylib) that the injector will load and use against the target application.
Additionally, make sure to change the dylib load path inside <code>runtime_injection_injector/main.cpp</code> (line 82) so it finds the compiled dylib. (Absolute paths recommended)