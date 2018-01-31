# Switchtec Kernel Design Documentation

This document aims to provide a jumping off point to working with the
kernel code for the switchtec driver. It describes some core concepts
and landmarks to help get started hacking on the code. This document
may not stay up to date so when in doubt, consult the code.

The Switchtec kernel module is divided into two parts: switchtec.ko and
ntb_hw_switchtec.ko. The former enumerates management and NTB endpoints,
configures them, and provides the interface to switchtec-user. The later
provides a driver for the Linux NTB stack. ntb_hw_switchtec.ko depends on
switchtec.ko.

## switchtec.ko

The main Switchtec driver enumerates the devices in the standard way
for Linux (how that is done is not covered in this document, for more
information on Linux Driver implementations refer to [LDD3][1] or the
Kernel source code).

### Userspace Interface

Refer to the README file or switchtec_ioclt.h for more information on
how the userspace interface is defined. The kernel module creates a
character device for each switch that was enumerated. Reading and
writing this device allows for creating MRPC commands and a few IOCTLs
are provided so userspace does not have to directly access the GAS
(which requires full root permission and has security and stability
implications). For the implementation of these commands refer to
switchtec_fops in switchtec.c.

Whenever a userspace application opens a switchtec char device, the
kernel creates a switchtec_user structure. This structure is used for
queueing MRPC commands so each application can have one MRPC command in
flight at a time and the kernel will arbitrate between the applications
on a first in first out basis.

When the application does a write, the kernel will queue the data to be
sent to the firmware. If the queue is empty, it will immediately submit
the command (see mrpc_queue_cmd). A read command will store how much data
is to be read and block until the command has been completed. An event
interrupt indicates when the command is completed and the kernel will
read the output data and store it in the switchtec_user structure (see
mrpc_complete_cmd). If the read command has not yet set how much output
data is expected the kernel will read all of the data into the buffer
(which may be slower than expected). Once the data is read the completion
in switchtec_user will signal the read command to return the data
to userspace.

In case something unexpected happens the kernel has a timeout on all
MRPC commands (see mrpc_timeout_work). Usually the interrupt will occur
before the timeout but if it is missed the timeout will prevent the
queue from being hung. Note: however if the firmware never indicates the
command is complete this will still hang the queue.

### Interrupts

The driver sets up space for up to four MSI-X or MSI interrupts but only
registers a handler for the event interrupt as designated by the
vep_vector_number in the GAS region. The NTB module will also register
another interrupt handler for the doorbell and message vector.

The event interrupt (switchtec_event_isr) first checks if the MRPC event
occurred and queues mrpc_work which will call mrpc_complete_cmd. It will
then clear the EVENT_OCCURRED bit so the interrupt doesn't continue to
trigger.

Next, the interrupt will check all the link state events in all the
ports and signal a link_notifier (typically used by the NTB driver)
if such an event occurs.

Finally, the interrupt will check all other event interrupts. If
an event interrupt occurs it wakes up any process that is polling
on events (see switchtec_dev_poll). It then disables the interrupt
for that event. In this way, it is expected that an application will
enable the interrupt it's waiting for, then call poll in a loop
checking for if the expected interrupt occurs. poll will return anytime
any event occurs.

### IOCTLs

A number of IOCTLs are provided for a number of functions needed by
switchtec-user. See the README for a description of these IOCTLs and
switchtec_dev_ioctl for their implementation.

### Sysfs

There are a number of sysfs attributes provided so that userspace can
easily enumerate and discover the available switchtec devices. The
attributes in the system can easily by browsed in sysfs under
/sys/class/switchtec.

These attributes are documented in Documentation/ABI/sysfs-class-switchtec.
See switchtec_device_attrs in switchtec.c for their implementation.

## ntb_hw_switchtec.ko

The ntb_hw_switchtec enumerates all devices in the switchtec class
and creates NTB interfaces for any devices that are NTB endpoints.
See switchtec_ntb_ops for the implementation of all the NTB operations.

### Shared Memory Window

The Switchtec NTB driver reserves one of the LUT memory windows so it
can be used to provide scratch pad registers and link detection. For
now, the driver sets the size of all LUT windows to be fixed at 64KB.
This size allows for the combined size of all LUT windows to be
sufficent enough that the alignment of the direct window that follows
will be at least 2MB.

### Link Management

The link is considered to be up when both sides have setup their shared
memory window and a magic number and link status must be read by both
sides to realize that the link is up. When either side changes their
link status, a specific message is sent telling the otherside to check
the current link state. The link state is also checked whenever the
switch sends a link state change interrupt.

### Memory windows

By default, the driver only provides direct memory windows to the
upper layers. This is because the existing upper layers can get confused
by a large number of LUT memory windows. The LUT memory windows can be
enabled with the use_lut_mws parameter.

### Crosslink

The crosslink feature allows for an NTB system to be entirely symmetric
such that two hosts can be identical and interchangeable. To do this a
special hostless partition is created in the middle of the two hosts.
This is supported by the driver and only requires a special initialization
procedure (see switchtec_ntb_init_crosslink). Crosslink also reserves another
one of the LUT windows to be used to window the NTB register space inside
the crosslink partition. Besides this, all other NTB operations function
identically to regular NTB.

[1]: https://lwn.net/Kernel/LDD3/
