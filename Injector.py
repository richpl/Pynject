#! /usr/bin/python

"""
Performs DLL injection on a Windows process. Methods are
provided to support two techniques, either injection of the
library path into the process and execution using LoadLibraryA,
or injection of the entire DLL itself.
"""

from ctypes import *
from ctypes.wintypes import *
from sys import stderr
import os


class Injector:
    # Import the required Windows DLLs
    # PSAPI.DLL
    # psapi = windll.psapi
    # Kernel32.DLL
    __kernel = windll.kernel32

    # Flags
    # PROCESS_QUERY_INFORMATION = 0x0400
    # PROCESS_VM_READ = 0x0010

    # __MEM_COMMIT = 0x00001000
    # __PAGE_EXECUTE_WRITECOPY = 0x80

    def get_proc_handle(self, pid):
        """
        Returns a handle to the process
        specified by the process ID

        :param pid: The process ID

        :return: A handle to the process, if it can
        be obtained
        """

        # Obtain a handle to the process with the
        # specified ID
        h_process = self.__kernel.OpenProcess(self.__kernel.PROCESS_QUERY_INFORMATION |
                                              self.__kernel.PROCESS_VM_READ |
                                              self.__kernel.PROCESS_CREATE_THREAD |
                                              self.__kernel.PROCESS_VM_OPERATION |
                                              self.__kernel.PROCESS_VM_WRITE |,
                                              False, pid)

        if not h_process:
            print("Could not obtain process handle!", file=stderr)

            # TODO Raise an exception here

        return h_process

    def get_dll_handle(self, dll_path):
        """
        Returns a handle to the DLL specified by the
        DLL path string

        :param dll_path: The path of the DLL

        :return: A handle to the DLL, if it can be obtained
        """
        # TODO Check that a valid path has been supplied

        # Open a handle to the DLL to be injected
        h_dll = self.__kernel.CreateFileA(dll_path,
                                           self.__kernel.GENERIC_READ,
                                           0,
                                           None,
                                           self.__kernel.OPEN_EXISTING,
                                           self.__kernel.FILE_ATTRIBUTE_NORMAL,
                                           None);

        return h_dll

    def write_path_into_process_memory(self, h_process, dll_path):
        """
        Writes the specified DLL path to the process memory, after
        allocating enough memory.

        :param h_process: A handle to the process to
        which we are writing
        :param dll_path: The DLL path that is to be written
        to the process memory

        :return: Either success (nonzero) or failure (zero)
        """

        # Establish the length of the DLL path
        # TODO Check that a valid path has been supplied
        __dw_size = c_size_t(len(dll_path))

        __base_address = \
            self.__kernel.VirtualAllocEx(h_process, 0,
                                         self.__dw_size,
                                         self.__kernel.MEM_COMMIT,
                                         self.__kernel.PAGE_EXECUTE_WRITECOPY)

        if __base_address:

            # Establish the length of the DLL path
            __dw_size = c_size_t(len(dll_path))

            # Set up output parameter to hold number of bytes written
            __num_bytes_written = c_size_t()

            __success = self.__kernel.WriteProcessMemory(h_process, 0,
                                                         dll_path, __dw_size,
                                                         byref(__num_bytes_written))

            # This will only succeed if we wrote the entire DLL
            if __num_bytes_written != len(dll_path):

                __success = 0
                print("Could not write all path bytes to process address space",
                      file=stderr)

        else:

            __success == 0

        return __success

    def write_dll_into_process_memory(self, h_process, dll_path):
        """
        Writes the specified DLL to the process memory.

        :param h_process: A handle to the process to
        which we are writing
        :param dll_path: The path of the DLL that is to be written
        to the process memory

        :return: Either success (nonzero) or failure (zero)
        """

        # TODO Check that a valid path has been supplied

        h_dll = self.get_dll_handle(dll_path)

        if h_dll:

            # Establish the size of the DLL
            dll_size = os.path.getsize(h_dll);
            __dw_size = c_size_t(dll_size)

            __base_address = \
                self.__kernel.VirtualAllocEx(h_process, 0,
                                             self.__dw_size,
                                             self.__kernel.MEM_COMMIT,
                                             self.__kernel.PAGE_EXECUTE_WRITECOPY)

        if __base_address:

            # Read DLL into a buffer before copying to remote
            # process
            # TODO

            # Copy into process memory
            # First, set up output parameter to hold number of bytes written
            __num_bytes_written = c_size_t()

            # TODO

            # This will only succeed if we wrote the entire DLL
            if __num_bytes_written != dll_size:

                __success = 0
                print("Could not write all DLL bytes to process address space",
                      file=stderr)

        else:

            __success = 0

        return __success

    def start_new_thread(self, h_process, base_address):
        """"""

        # Resolve the location of the LoadLibraryA function
        h_kernel = self.__kernel.GetModuleHandleA("kernel32.dll")
        load_lib_addr = self.__kernel.GetProcAddress(h_kernel, "LoadLibraryA")

        # Set thread flag for immediate execution,
        # i.e. do not create in suspended state
        __dw_creation_flags = DWORD(0)

        # Create a thread with default security attributes,
        # default thread stack size, ,
        __h_thread = self.__kernel.CreateRemoteThread(h_process, None,
                                                      0, load_lib_addr,
                                                      base_address,
                                                      __dw_creation_flags,
                                                      None)

        if not __h_thread:
            print("Could not obtain thread handle!", file=stderr)

            # TODO Raise an exception here

        return __h_thread


    def release(self, h_process):
        """
        Release the process handle.

        :param h_process: The handle to be released
        :return: Either success (nonzero) or failure (zero)
        """
        return self.__kernel.CloseHandle(h_process)

    def inject_using_path(self, pid, dll_path):
        """
        Loads the path of the DLL to be injected into the
        target process, then causes the target to load that
        DLL from the specified path

        :param pid: The process ID of the process into
        which we are injecting
        :param dll_path: The path of the DLL that we are going
        to inject

        :return: Zero for unsuccessful, non-zero for success
        """

        success = 0

        # Obtain a handle to the process we wish to examine
        h_process = self.get_proc_handle(pid)

        # Allocate enough memory in the process
        # to accommodate the DLL
        base_address = self.allocate_process_memory(h_process, dll_path)

        if base_address:

            # Write the DLL to the allocated memory
            success = self.write_process_memory(h_process, dll_path)

            if success:

                # Create remote thread within injected process
                # and start executing the DLL
                self.start_new_thread(h_process, base_address)

                # Release the handle
                success = self.release(h_process)

                if not success:
                    print("Could not release handle")

        return success

    def inject_directly(self, pid, dll_path):
        """
        Directly loads the DLL into the target process
        before executing it.

        :param pid: The process ID of the process into
        which we are injecting
        :param dll_path: The path of the DLL that we are going
        to inject

        :return: Zero for unsuccessful, non-zero for success
        """
        # TODO

if __name__ == "__main__":

    # ID of the process into which we are injecting
    pid = 100

    # Path to DLL to be injected
    # TODO Find suitable DLL to inject
    dll_path = "c:\\"

    injector = Injector()
    injector.inject_using_path(pid, dll_path)

