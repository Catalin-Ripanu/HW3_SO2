// SPDX-License-Identifier: GPL-2.0+

/*
 * Linux UART char device
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/io.h>
#include <linux/kfifo.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "uart16550.h"

#define MODULE_NAME "uart16550"

#define DEVICE_BUFFER_SIZE 1024

#define COM_ADDRS_NUM 8

#define DEVICE_MAJOR 42
#define COM1_PORT 0
#define COM2_PORT 1

#define COM1_BASE_ADDR 0x3f8
#define COM2_BASE_ADDR 0x2f8

#define MAX_COM_LENGTH 14

#define IRQ_COM1 4
#define IRQ_COM2 3

struct uart16550_device {
	struct cdev cdev;
	DECLARE_KFIFO(get_kfifo, char, DEVICE_BUFFER_SIZE);
	DECLARE_KFIFO(put_kfifo, char, DEVICE_BUFFER_SIZE);
	size_t base_addr;
	size_t get_idx;
	size_t put_idx;
	wait_queue_head_t get_queue;
	wait_queue_head_t put_queue;
	atomic_t finish_get;
	atomic_t finish_put;
};

static struct uart16550_device devices[MAX_NUMBER_DEVICES];

static int major = DEVICE_MAJOR;
module_param(major, int, 0660);
MODULE_PARM_DESC(major, "Major of the device (default = 42)");

static int minor_dev[MAX_NUMBER_DEVICES] = {0, 0};
static int dev_num;
static int uart16550_minor;

static unsigned long option = OPTION_BOTH;
module_param(option, ulong, 0660);
MODULE_PARM_DESC(option, "OPTION_BOTH = 3 | OPTION_COM2 = 2 | OPTION_COM1 = 1 (default = 3)");

static int uart16550_release(struct inode *inode, struct file *file)
{
	return 0;
}

/**
 * uart16550_open - device open operation
 * @inode: structure used for taking uart16550_device data
 * @file: file used for storing uart16550_device structure
 */
static int uart16550_open(struct inode *inode, struct file *file)
{
	struct uart16550_device *data = container_of(inode->i_cdev,
												 struct uart16550_device, cdev);

	file->private_data = data;
	return 0;
}

/**
 * uart16550_write - Perform device write operation
 * @file: file structure used for writing the echo request data
 * @user_buffer: user-space address holding the echo request data
 * @size: size of the write operation
 *
 * This function retrieves data from user-space, sets the Transmitter Holding
 * Register Empty (THR Empty) bit to 1 in the Interrupt Enable Register, and
 * then waits for the interrupt handler to handle this action with the assistance
 * of a waiting queue.
 * The interrupt handler will write the data into a kfifo for write operations.
 * After this thread wakes up, it reactivates the interrupts.
 */
static ssize_t uart16550_write(struct file *file,
							   const char __user *user_buffer, size_t size,
							   loff_t *offset)
{
	struct uart16550_device *dev = (struct uart16550_device *)file->private_data;
	size_t ier_address;
	size_t thr_offset = 0b00000010;
	int err = 0;

	if (!size)
		return 0;

	if (kfifo_from_user(&dev->put_kfifo, user_buffer, size > MAX_COM_LENGTH ? MAX_COM_LENGTH : size, &err))
		return -EFAULT;

	atomic_set(&dev->finish_put, 0);

	ier_address = dev->base_addr + 0b001;

	outb(inb(ier_address) | thr_offset, ier_address);

	if (wait_event_interruptible(dev->put_queue, atomic_read(&dev->finish_put) == 1))
		return -ERESTARTSYS;

	return dev->put_idx;
}

/**
 * uart16550_read - Perform device read operation
 * @file: file structure used for reading the data for the cat request
 * @user_buffer: user-space address to receive the kernel-space data
 * @size: size of the read operation
 *
 * This function waits for the interrupt handler to manage this action
 * with the assistance of a waiting queue, sends the content stored in the
 * kfifo to user-space, and sets the Data Ready bit to 1 in the Interrupt
 * Enable Register.
 * After this thread wakes up, it reactivates the interrupts.
 */
static ssize_t uart16550_read(struct file *file, char __user *user_buffer,
							  size_t size, loff_t *offset)
{
	struct uart16550_device *dev = (struct uart16550_device *)file->private_data;
	size_t ier_address;
	size_t data_ready_offset = 0b00000001;
	int err = 0;

	if (!size)
		return 0;

	if (wait_event_interruptible(dev->get_queue, atomic_read(&dev->finish_get) == 1))
		return -ERESTARTSYS;

	if (kfifo_to_user(&dev->get_kfifo, user_buffer, size, &err))
		return -EFAULT;

	atomic_set(&dev->finish_get, 0);

	ier_address = dev->base_addr + 0b001;

	outb(inb(ier_address) | data_ready_offset, ier_address);

	return err;
}

/**
 * uart16550_interrupt_handle - Handle interrupts for device
 * @dev_id: identifier of the device generating the interrupt
 *
 * This function manages both read and write interrupts by reading from
 * or writing to the user_buffer variable depending on the type of interrupt.
 * To determine the type, it checks the Interrupt Identification/Status Register,
 * where a value of xxxx010x indicates a read interrupt, and xxxx001x indicates
 * a write interrupt.
 *
 * For a write interrupt, it transfers data from the write operation kfifo to
 * the device. For a read interrupt, it transfers data from the device to the
 * read operation kfifo.
 *
 * In both cases, the waiting thread in the queue is awakened to resume its work.
 */
static irqreturn_t uart16550_interrupt_handle(int irq_no, void *dev_id)
{
	struct uart16550_device *dev = (struct uart16550_device *)dev_id;
	char user_buffer[MAX_COM_LENGTH];
	size_t iir_address_content = inb(dev->base_addr + 0b010);
	size_t ier_address = dev->base_addr + 0b001;
	size_t lsr_address = dev->base_addr + 0b101;
	size_t data_ready_offset = 0b00000001;
	int curr_get_idx = 0;

	if (iir_address_content & 0b010) {

		size_t thr_offset = 0b00000010;
		int curr_put_idx = 0;

		atomic_set(&dev->finish_put, 1);

		outb(~(~inb(ier_address) | thr_offset), ier_address);

		curr_get_idx = kfifo_out(&dev->put_kfifo, user_buffer, MAX_COM_LENGTH);

		while (curr_put_idx < curr_get_idx && (inb(lsr_address) & (thr_offset << 5))) {
			outb(user_buffer[curr_put_idx], dev->base_addr);
			++curr_put_idx;
		}

		dev->put_idx = curr_put_idx;

		wake_up_interruptible(&dev->put_queue);
	}

	if (iir_address_content & 0b100) {
		atomic_set(&dev->finish_get, 1);

		while ((inb(lsr_address) & data_ready_offset) && curr_get_idx < MAX_COM_LENGTH) {
			user_buffer[curr_get_idx] = inb(dev->base_addr);
			++curr_get_idx;
		}

		outb(~(~inb(ier_address) | data_ready_offset), ier_address);

		kfifo_in(&dev->get_kfifo, user_buffer, curr_get_idx);
		dev->get_idx = curr_get_idx;

		wake_up_interruptible(&dev->get_queue);
	}

	return IRQ_HANDLED;
}

/**
 * uart16550_ioctl - IO controller for device
 * @file: UART device structure data
 * @cmd: ioctl command from user-space
 * @arg: ioctl argument from user-space
 *
 * This function configures the UART protocol using the parameters received
 * from user-space and activates the corresponding bits (stop bit, len bit,
 * parity bit, baud, fifo).
 */
static long uart16550_ioctl(struct file *file, unsigned int cmd,
							unsigned long arg)
{
	struct uart16550_line_info user_space_info;
	struct uart16550_device *dev =
		(struct uart16550_device *)file->private_data;

	if (cmd == UART16550_IOCTL_SET_LINE) {

		size_t lcr_address;
		size_t fifo_data_error_offset = 0b10000000;

		if (copy_from_user(&user_space_info, (const void __user *)arg, sizeof(user_space_info)))
			return -EFAULT;

		lcr_address = dev->base_addr + 0b011;

		outb(inb(lcr_address) | fifo_data_error_offset, lcr_address);
		outb(user_space_info.baud, dev->base_addr);

		outb(user_space_info.stop, lcr_address);

		outb(user_space_info.len, lcr_address);

		outb(user_space_info.par, lcr_address);

		return 0;
	}
	return -EINVAL;
}

/**
 * Structure for storing all possible operations
 * for device.
 */
static const struct file_operations uart16550_fops = {
	.owner = THIS_MODULE,
	.open = uart16550_open,
	.read = uart16550_read,
	.write = uart16550_write,
	.release = uart16550_release,
	.unlocked_ioctl = uart16550_ioctl,
};

/**
 * init_uart_device - Initialize UART devices
 * @num_irq: interrupt number of the device
 * @dev_identifier: minor number of the device
 * @base_addr: base address of the port
 *
 * This function creates a new char device with its IRQ number and region.
 * It initializes all device fields and sets the bits so that UART will use
 * kfifo structures and will set the dimension of the data to 14 bytes.
 */
int init_uart_device(size_t num_irq, size_t dev_identifier, size_t base_addr)
{
	int err;

	size_t out_one_offset = 0b00000100;
	size_t data_ready_offset = 0b00000001;
	size_t fifo_settings = 0b00000001;

	cdev_init(&devices[dev_identifier].cdev, &uart16550_fops);

	err = cdev_add(&devices[dev_identifier].cdev,
				   MKDEV(DEVICE_MAJOR, dev_identifier), 1);
	if (err < 0)
		return err;

	if (request_region(base_addr, COM_ADDRS_NUM, MODULE_NAME) == NULL) {
		err = -EBUSY;
		return err;
	}

	err = request_irq(num_irq, uart16550_interrupt_handle, IRQF_SHARED,
					  MODULE_NAME, &devices[dev_identifier]);
	if (err != 0)
		return err;

	devices[dev_identifier].base_addr = base_addr;

	outb(out_one_offset, devices[dev_identifier].base_addr + 0b100);

	atomic_set(&devices[dev_identifier].finish_get, 0);
	atomic_set(&devices[dev_identifier].finish_put, 0);

	devices[dev_identifier].put_idx = 0;
	devices[dev_identifier].get_idx = 0;

	outb(data_ready_offset, devices[dev_identifier].base_addr + 0b001);

	init_waitqueue_head(&devices[dev_identifier].get_queue);
	init_waitqueue_head(&devices[dev_identifier].put_queue);

	outb(fifo_settings | fifo_settings << 1 |
			 fifo_settings << 2 | fifo_settings << 6 | fifo_settings << 7,
		 devices[dev_identifier].base_addr + 0b010);

	INIT_KFIFO(devices[dev_identifier].get_kfifo);
	INIT_KFIFO(devices[dev_identifier].put_kfifo);

	return 0;
}

/**
 * destroy_uart_device - Destroy UART devices
 * @num_irq: interrupt number of the device
 * @dev_identifier: minor number of the device
 * @base_addr: base address of the port
 *
 * This function frees the device regions and empties the used registers.
 */
static void destroy_uart_device(size_t num_irq, size_t dev_identifier, size_t base_addr)
{
	kfifo_free(&devices[dev_identifier].get_kfifo);
	kfifo_free(&devices[dev_identifier].put_kfifo);

	cdev_del(&devices[dev_identifier].cdev);

	free_irq(num_irq, &devices[dev_identifier]);

	release_region(base_addr, COM_ADDRS_NUM);
}

/**
 * uart16550_init - Initialize character devices
 *
 * This function initializes the module. It frees registered variables
 * if failure is encountered during this initialization phase.
 */
static int uart16550_init(void)
{
	int err = 0;

	if (option == OPTION_BOTH) {
		dev_num = 2;
		minor_dev[COM1_PORT] = 1;
		minor_dev[COM2_PORT] = 1;
	} else if (option == OPTION_COM1) {
		dev_num = 1;
		minor_dev[COM1_PORT] = 1;
		minor_dev[COM2_PORT] = 0;
	} else if (option == OPTION_COM2) {
		dev_num = 1;
		minor_dev[COM1_PORT] = 0;
		minor_dev[COM2_PORT] = 1;
	} else {
		err = -EINVAL;
		goto out;
	}

	if (dev_num == MAX_NUMBER_DEVICES)
		uart16550_minor = 0;
	else {
		if (option == OPTION_COM2)
			uart16550_minor = COM2_PORT;
		else if (option == OPTION_COM1)
			uart16550_minor = COM1_PORT;
	}

	err = register_chrdev_region(MKDEV(DEVICE_MAJOR,
										uart16550_minor),
									  dev_num, MODULE_NAME);
	if (err != 0)
		goto out;

	if (minor_dev[COM1_PORT]) {
		err = init_uart_device(IRQ_COM1, COM1_PORT, COM1_BASE_ADDR);

		if (err != 0) {
			if (err == -EBUSY)
				goto out_unregister;
			else
				goto out_release_region;
		}
	}

	if (minor_dev[COM2_PORT]) {
		err = init_uart_device(IRQ_COM2, COM2_PORT, COM2_BASE_ADDR);

		if (err != 0) {
			if (option == OPTION_BOTH && err == -EBUSY)
				goto out_release_region;
			else if (option == OPTION_BOTH && err != -EBUSY)
				goto out_release_regions;
			else if (option == COM2_PORT && err == -EBUSY)
				goto out_unregister;
			else if (option == COM2_PORT && err != -EBUSY) {
				release_region(COM2_BASE_ADDR, COM_ADDRS_NUM);
				goto out_unregister;
			}
		}
	}

	return 0;

out_release_regions:
	release_region(COM2_BASE_ADDR, COM_ADDRS_NUM);
out_release_region:
	release_region(COM1_BASE_ADDR, COM_ADDRS_NUM);

out_unregister:
	unregister_chrdev_region(MKDEV(DEVICE_MAJOR, uart16550_minor), dev_num);
out:
	return err;
}

/**
 * uart16550_exit - Free used resources (regions, IRQs, etc)
 *
 * This function is responsible for freeing used regions, registers, IRQs,
 * and deleting all created character devices.
 */
static void uart16550_exit(void)
{
	if (minor_dev[COM1_PORT])
		destroy_uart_device(IRQ_COM1, COM1_PORT, COM1_BASE_ADDR);

	if (minor_dev[COM2_PORT])
		destroy_uart_device(IRQ_COM2, COM2_PORT, COM2_BASE_ADDR);

	unregister_chrdev_region(MKDEV(DEVICE_MAJOR, uart16550_minor), dev_num);
}

module_init(uart16550_init);
module_exit(uart16550_exit);

MODULE_DESCRIPTION("UART char device implementation");

MODULE_AUTHOR("Catalin-Alexandru Ripanu catalin.ripanu@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");
