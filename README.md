# HW3_SO2

A kernel module that implements a driver for the serial port (UART16550).

The device driver supports the two standard serial ports in a PC, COM1 and COM2 (0x3f8 and 0x2f8, in fact the entire range of 8 addresses 0x3f8-0x3ff and 0x2f8-0x2ff specific to the two ports). In addition to the standard routines (open, read, write, close), the driver must also have support for changing communication parameters using an ioctl operation (UART16550_IOCTL_SET_LINE).

The driver uses interrupts for both reception and transmission to reduce latency and CPU usage time. Read and write calls must also be blocking. A buffer for the read routine and another buffer for the write routine for each serial port in the driver are being used.

A blocking read call means that the read routine called from the user-space will be blocked until at least one byte is read (the read buffer in the kernel is empty and no data can be read). A blocking write call means that the write routine called from the user-space will be blocked until at least one byte is written (the write buffer in the kernel is full and no data can be written).

![alt text](https://github.com/CatalinACS/HW3_SO2/blob/main/buffers-scheme.png)

Data transfer between the various buffers is a Producer-Consumer problem. Example:

- The process is the producer and the device is the consumer if it is written from the process to the device; the process will block until there is at least one free space in the consumer's buffer

- The process is the consumer and the device is the producer if it is read from a process from the device; the process will block until there is at least one element in the producer's buffer.

## Implementation details:

- The driver is implemented as a kernel module named uart16550.ko

- The driver is be accessed as a character device driver, with different functions depending on the parameters transmitted to the load module:

    - the major parameter will specify the major with which the device must be registered

    - the option parameter will specify how it works:

      - OPTION_BOTH: will also register COM1 and COM2, with the major given by the major parameter and the minors 0 (for COM1) and 1 (for COM2);
  
      - OPTION_COM1: will only register COM1, with the major major and minor 0;
  
      - OPTION_COM2: will only register COM2, with the major major and minor 1;
  
    - the default values are major=42 and option=OPTION_BOTH.

    - the interrupt number associated with COM1 is 4 (IRQ_COM1) and the interrupt number associated with COM2 is 3 (IRQ_COM2)

    - the header with the definitions needed for special operations;
  
    - used synchronization with waiting queues

    - In order for the assigment to work, the default serial driver must be disabled:

      - `cat /proc/ioports | grep serial` will detect the presence of the default driver on the regions where COM1 and COM2 are defined
    
        - in order to deactivate it, the kernel must be recompiled, either by setting the serial driver as the module, or by deactivating it completely.
