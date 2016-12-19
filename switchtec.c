/*
 * Microsemi Switchtec(tm) PCIe Management Driver
 * Copyright (c) 2016, Microsemi Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include "switchtec.h"
#include <linux/switchtec_ioctl.h>

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/poll.h>

MODULE_DESCRIPTION("Microsemi Switchtec(tm) PCI-E Management Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsemi Corporation");

static int max_devices = 16;
module_param(max_devices, int, S_IRUGO);
MODULE_PARM_DESC(max_devices, "max number of switchtec device instances");

static dev_t switchtec_devt;
static struct class *switchtec_class;
static DEFINE_IDA(switchtec_minor_ida);

static struct switchtec_dev *to_stdev(struct device *dev)
{
	return container_of(dev, struct switchtec_dev, dev);
}

struct switchtec_user {
	struct switchtec_dev *stdev;

	enum mrpc_state {
		MRPC_IDLE = 0,
		MRPC_QUEUED,
		MRPC_RUNNING,
		MRPC_DONE,
	} state;

	struct completion comp;
	struct kref kref;
	struct list_head list;

	u32 cmd;
	u32 status;
	u32 return_code;
	size_t data_len;
	unsigned char data[SWITCHTEC_MRPC_PAYLOAD_SIZE];
};

static struct switchtec_user *stuser_create(struct switchtec_dev *stdev)
{
	struct switchtec_user *stuser;

	stuser = kzalloc(sizeof(*stuser), GFP_KERNEL);
	if (!stuser)
		return ERR_PTR(-ENOMEM);

	get_device(&stdev->dev);
	stuser->stdev = stdev;
	kref_init(&stuser->kref);
	INIT_LIST_HEAD(&stuser->list);
	init_completion(&stuser->comp);

	dev_dbg(&stdev->dev, "%s: %p\n", __func__, stuser);

	return stuser;
}

static void stuser_free(struct kref *kref)
{
	struct switchtec_user *stuser;

	stuser = container_of(kref, struct switchtec_user, kref);

	dev_dbg(&stuser->stdev->dev, "%s: %p\n", __func__, stuser);

	put_device(&stuser->stdev->dev);
	kfree(stuser);
}

static void stuser_put(struct switchtec_user *stuser)
{
	kref_put(&stuser->kref, stuser_free);
}

static void stuser_set_state(struct switchtec_user *stuser,
			     enum mrpc_state state)
{
	const char * const state_names[] = {
		[MRPC_IDLE] = "IDLE",
		[MRPC_QUEUED] = "QUEUED",
		[MRPC_RUNNING] = "RUNNING",
		[MRPC_DONE] = "DONE",
	};

	stuser->state = state;

	dev_dbg(stdev_dev(stuser->stdev), "stuser state %p -> %s",
		stuser, state_names[state]);
}

static int stdev_is_alive(struct switchtec_dev *stdev)
{
	return stdev->mmio != NULL;
}

static void mrpc_complete_cmd(struct switchtec_dev *stdev);

static void mrpc_cmd_submit(struct switchtec_dev *stdev)
{
	/* requires the mrpc_mutex to already be held when called */

	struct switchtec_user *stuser;

	if (stdev->mrpc_busy)
		return;

	if (list_empty(&stdev->mrpc_queue))
		return;

	stuser = list_entry(stdev->mrpc_queue.next, struct switchtec_user,
			    list);

	stuser_set_state(stuser, MRPC_RUNNING);
	stdev->mrpc_busy = 1;
	memcpy_toio(&stdev->mmio_mrpc->input_data,
		    stuser->data, stuser->data_len);
	iowrite32(stuser->cmd, &stdev->mmio_mrpc->cmd);

	stuser->status = ioread32(&stdev->mmio_mrpc->status);
	if (stuser->status != SWITCHTEC_MRPC_STATUS_INPROGRESS)
		mrpc_complete_cmd(stdev);

	schedule_delayed_work(&stdev->mrpc_timeout,
			      msecs_to_jiffies(500));
}

static void mrpc_queue_cmd(struct switchtec_user *stuser)
{
	/* requires the mrpc_mutex to already be held when called */

	struct switchtec_dev *stdev = stuser->stdev;

	kref_get(&stuser->kref);
	stuser_set_state(stuser, MRPC_QUEUED);
	init_completion(&stuser->comp);
	list_add_tail(&stuser->list, &stdev->mrpc_queue);

	mrpc_cmd_submit(stdev);
}

static void mrpc_complete_cmd(struct switchtec_dev *stdev)
{
	/* requires the mrpc_mutex to already be held when called */
	struct switchtec_user *stuser;

	if (list_empty(&stdev->mrpc_queue))
		return;

	stuser = list_entry(stdev->mrpc_queue.next, struct switchtec_user,
			    list);

	stuser->status = ioread32(&stdev->mmio_mrpc->status);
	if (stuser->status == SWITCHTEC_MRPC_STATUS_INPROGRESS)
		return;

	stuser_set_state(stuser, MRPC_DONE);
	stuser->return_code = 0;

	if (stuser->status != SWITCHTEC_MRPC_STATUS_DONE)
		goto out;

	stuser->return_code = ioread32(&stdev->mmio_mrpc->ret_value);
	if (stuser->return_code != 0)
		goto out;

	memcpy_fromio(stuser->data, &stdev->mmio_mrpc->output_data,
		      sizeof(stuser->data));

out:
	complete_all(&stuser->comp);
	list_del_init(&stuser->list);
	stuser_put(stuser);
	stdev->mrpc_busy = 0;

	mrpc_cmd_submit(stdev);
}

static void mrpc_event_work(struct work_struct *work)
{
	struct switchtec_dev *stdev;

	stdev = container_of(work, struct switchtec_dev, mrpc_work);

	dev_dbg(stdev_dev(stdev), "%s\n", __func__);

	mutex_lock(&stdev->mrpc_mutex);
	cancel_delayed_work(&stdev->mrpc_timeout);
	mrpc_complete_cmd(stdev);
	mutex_unlock(&stdev->mrpc_mutex);
}

static void mrpc_timeout_work(struct work_struct *work)
{
	struct switchtec_dev *stdev;
	u32 status;

	stdev = container_of(work, struct switchtec_dev, mrpc_timeout.work);

	dev_dbg(stdev_dev(stdev), "%s\n", __func__);

	mutex_lock(&stdev->mrpc_mutex);

	if (stdev_is_alive(stdev)) {
		status = ioread32(&stdev->mmio_mrpc->status);
		if (status == SWITCHTEC_MRPC_STATUS_INPROGRESS) {
			schedule_delayed_work(&stdev->mrpc_timeout,
					      msecs_to_jiffies(500));
			goto out;
		}
	}

	mrpc_complete_cmd(stdev);

out:
	mutex_unlock(&stdev->mrpc_mutex);
}

static ssize_t device_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct switchtec_dev *stdev = to_stdev(dev);
	uint32_t ver;

	ver = ioread32(&stdev->mmio_sys_info->device_version);

	return sprintf(buf, "%x\n", ver);
}
static DEVICE_ATTR_RO(device_version);

static ssize_t fw_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct switchtec_dev *stdev = to_stdev(dev);
	uint32_t ver;

	ver = ioread32(&stdev->mmio_sys_info->firmware_version);

	return sprintf(buf, "%08x\n", ver);
}
static DEVICE_ATTR_RO(fw_version);

static ssize_t io_string_show(char *buf, void __iomem *attr, size_t len)
{
	int i;

	memcpy_fromio(buf, attr, len);
	buf[len] = '\n';
	buf[len+1] = 0;

	for (i = len-1; i > 0; i--) {
		if (buf[i] != ' ')
			break;
		buf[i] = '\n';
		buf[i+1] = 0;
	}

	return strlen(buf);
}

#define DEVICE_ATTR_SYS_INFO_STR(field) \
static ssize_t field ## _show(struct device *dev, \
			      struct device_attribute *attr, char *buf) \
{ \
	struct switchtec_dev *stdev = to_stdev(dev); \
	return io_string_show(buf, &stdev->mmio_sys_info->field, \
			    sizeof(stdev->mmio_sys_info->field)); \
} \
 \
static DEVICE_ATTR_RO(field);

DEVICE_ATTR_SYS_INFO_STR(vendor_id);
DEVICE_ATTR_SYS_INFO_STR(product_id);
DEVICE_ATTR_SYS_INFO_STR(product_revision);
DEVICE_ATTR_SYS_INFO_STR(component_vendor);

static ssize_t component_id_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct switchtec_dev *stdev = to_stdev(dev);
	int id = ioread16(&stdev->mmio_sys_info->component_id);
	return sprintf(buf, "PM%04X\n", id);
}
static DEVICE_ATTR_RO(component_id);

static ssize_t component_revision_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct switchtec_dev *stdev = to_stdev(dev);
	int rev = ioread8(&stdev->mmio_sys_info->component_revision);
	return sprintf(buf, "%d\n", rev);
}
static DEVICE_ATTR_RO(component_revision);

static struct attribute *switchtec_device_attrs[] = {
	&dev_attr_device_version.attr,
	&dev_attr_fw_version.attr,
	&dev_attr_vendor_id.attr,
	&dev_attr_product_id.attr,
	&dev_attr_product_revision.attr,
	&dev_attr_component_vendor.attr,
	&dev_attr_component_id.attr,
	&dev_attr_component_revision.attr,
	NULL,
};

ATTRIBUTE_GROUPS(switchtec_device);


static int switchtec_dev_open(struct inode *inode, struct file *filp)
{
	struct switchtec_dev *stdev;
	struct switchtec_user *stuser;

	stdev = container_of(inode->i_cdev, struct switchtec_dev, cdev);

	stuser = stuser_create(stdev);
	if (!stuser)
		return PTR_ERR(stuser);

	filp->private_data = stuser;
	nonseekable_open(inode, filp);

	dev_dbg(stdev_dev(stdev), "%s: %p\n", __func__, stuser);

	return 0;
}

static int switchtec_dev_release(struct inode *inode, struct file *filp)
{
	struct switchtec_user *stuser = filp->private_data;

	stuser_put(stuser);

	return 0;
}

static ssize_t switchtec_dev_write(struct file *filp, const char __user *data,
				   size_t size, loff_t *off)
{
	struct switchtec_user *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;
	int rc;

	if (!stdev_is_alive(stdev))
		return -ENXIO;

	if (size < sizeof(stuser->cmd) ||
	    size > sizeof(stuser->cmd) + SWITCHTEC_MRPC_PAYLOAD_SIZE)
		return -EINVAL;

	if (mutex_lock_interruptible(&stdev->mrpc_mutex))
		return -EINTR;

	if (stuser->state != MRPC_IDLE) {
		rc = -EBADE;
		goto out;
	}

	rc = copy_from_user(&stuser->cmd, data, sizeof(stuser->cmd));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	data += sizeof(stuser->cmd);
	rc = copy_from_user(&stuser->data, data, size - sizeof(stuser->cmd));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	stuser->data_len = size - sizeof(stuser->cmd);

	mrpc_queue_cmd(stuser);

	rc = size;

out:
	mutex_unlock(&stdev->mrpc_mutex);

	return rc;
}

static ssize_t switchtec_dev_read(struct file *filp, char __user *data,
				  size_t size, loff_t *off)
{
	struct switchtec_user *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;
	int rc;

	if (!stdev_is_alive(stdev))
		return -ENXIO;

	if (size < sizeof(stuser->cmd) ||
	    size >= sizeof(stuser->cmd) + SWITCHTEC_MRPC_PAYLOAD_SIZE)
		return -EINVAL;

	if (stuser->state == MRPC_IDLE)
		return -EBADE;

	if (filp->f_flags & O_NONBLOCK) {
		if (!try_wait_for_completion(&stuser->comp))
			return -EAGAIN;
	} else {
		rc = wait_for_completion_interruptible(&stuser->comp);
		if (rc < 0)
			return rc;
	}

	if (mutex_lock_interruptible(&stdev->mrpc_mutex))
		return -EINTR;

	if (stuser->state != MRPC_DONE)
		return -EBADE;

	rc = copy_to_user(data, &stuser->return_code,
			  sizeof(stuser->return_code));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	data += sizeof(stuser->return_code);
	rc = copy_to_user(data, &stuser->data,
			  size - sizeof(stuser->return_code));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	stuser_set_state(stuser, MRPC_IDLE);

	if (stuser->status == SWITCHTEC_MRPC_STATUS_DONE)
		rc = size;
	else if (stuser->status == SWITCHTEC_MRPC_STATUS_INTERRUPTED)
		rc = -ENXIO;
	else
		rc = -EBADMSG;

out:
	mutex_unlock(&stdev->mrpc_mutex);

	return rc;
}

static unsigned int switchtec_dev_poll(struct file *filp, poll_table *wait)
{
	struct switchtec_user *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;

	poll_wait(filp, &stuser->comp.wait, wait);

	if (!stdev_is_alive(stdev))
		return POLLERR;

	if (stuser->state == MRPC_IDLE)
		return POLLERR;
	else if (try_wait_for_completion(&stuser->comp))
		return POLLIN | POLLRDNORM;

	return 0;
}

static int ioctl_fw_info(struct switchtec_dev *stdev,
			 struct switchtec_ioctl_fw_info __user *uinfo)
{
	struct switchtec_ioctl_fw_info info;

	#define fw_info_set(field) \
		info.field = ioread32(&stdev->mmio_flash_info->field)

	fw_info_set(flash_part_map_upd_idx);
	fw_info_set(active_main_fw.address);
	fw_info_set(active_main_fw.build_version);
	fw_info_set(active_main_fw.build_string);
	fw_info_set(active_cfg.address);
	fw_info_set(active_cfg.build_version);
	fw_info_set(active_cfg.build_string);
	fw_info_set(inactive_main_fw.address);
	fw_info_set(inactive_main_fw.build_version);
	fw_info_set(inactive_main_fw.build_string);
	fw_info_set(inactive_cfg.address);
	fw_info_set(inactive_cfg.build_version);
	fw_info_set(inactive_cfg.build_string);

	if (copy_to_user(uinfo, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long switchtec_dev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	struct switchtec_user *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;

	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case SWITCHTEC_IOCTL_FW_INFO:
		return ioctl_fw_info(stdev, argp);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations switchtec_fops = {
	.owner = THIS_MODULE,
	.open = switchtec_dev_open,
	.release = switchtec_dev_release,
	.write = switchtec_dev_write,
	.read = switchtec_dev_read,
	.poll = switchtec_dev_poll,
	.unlocked_ioctl = switchtec_dev_ioctl,
	.compat_ioctl = switchtec_dev_ioctl,
};

static void stdev_release(struct device *dev)
{
	struct switchtec_dev *stdev = to_stdev(dev);

	ida_simple_remove(&switchtec_minor_ida,
			  MINOR(dev->devt));
	kfree(stdev);
}

static void stdev_unregister(struct switchtec_dev *stdev)
{
	cdev_del(&stdev->cdev);
	device_unregister(stdev_dev(stdev));
}

static struct switchtec_dev *stdev_create(struct pci_dev *pdev)
{
	struct switchtec_dev *stdev;
	int minor;
	struct device *dev;
	struct cdev *cdev;
	int rc;

	stdev = kzalloc_node(sizeof(*stdev), GFP_KERNEL,
			     dev_to_node(&pdev->dev));
	if (!stdev)
		return ERR_PTR(-ENOMEM);

	stdev->pdev = pdev;
	INIT_LIST_HEAD(&stdev->mrpc_queue);
	mutex_init(&stdev->mrpc_mutex);
	stdev->mrpc_busy = 0;
	INIT_WORK(&stdev->mrpc_work, mrpc_event_work);
	INIT_DELAYED_WORK(&stdev->mrpc_timeout, mrpc_timeout_work);

	minor = ida_simple_get(&switchtec_minor_ida, 0, 0,
			       GFP_KERNEL);
	if (minor < 0)
		return ERR_PTR(minor);

	dev = &stdev->dev;
	device_initialize(dev);
	dev->devt = MKDEV(MAJOR(switchtec_devt), minor);
	dev->class = switchtec_class;
	dev->parent = &pdev->dev;
	dev->groups = switchtec_device_groups;
	dev->release = stdev_release;
	dev_set_name(dev, "switchtec%d", minor);

	cdev = &stdev->cdev;
	cdev_init(cdev, &switchtec_fops);
	cdev->owner = THIS_MODULE;
	cdev->kobj.parent = &dev->kobj;

	rc = cdev_add(&stdev->cdev, dev->devt, 1);
	if (rc)
		goto err_cdev;

	rc = device_add(dev);
	if (rc) {
		cdev_del(&stdev->cdev);
		put_device(dev);
		return ERR_PTR(rc);
	}

	return stdev;

err_cdev:
	ida_simple_remove(&switchtec_minor_ida, minor);

	return ERR_PTR(rc);
}

static irqreturn_t switchtec_event_isr(int irq, void *dev)
{
	struct switchtec_dev *stdev = dev;
	u32 summary;

	summary = ioread32(&stdev->mmio_part_cfg->part_event_summary);

	if (summary & SWITCHTEC_PART_CFG_EVENT_MRPC_CMP) {
		schedule_work(&stdev->mrpc_work);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int switchtec_init_msix_isr(struct switchtec_dev *stdev)
{
	struct pci_dev *pdev = stdev_pdev(stdev);
	int rc, i, msix_count, node;

	node = dev_to_node(&pdev->dev);

	stdev->msix = kzalloc_node(4 * sizeof(*stdev->msix),
				  GFP_KERNEL, node);
	if (!stdev->msix)
		return -ENOMEM;

	for (i = 0; i < 4; ++i)
		stdev->msix[i].entry = i;

	msix_count = pci_enable_msix_range(pdev, stdev->msix, 1, 4);
	if (msix_count < 0) {
		rc = msix_count;
		goto err_msix_enable;
	}

	stdev->event_irq = ioread32(&stdev->mmio_part_cfg->vep_vector_number);
	if (stdev->event_irq < 0 || stdev->event_irq >= msix_count) {
		rc = -EFAULT;
		goto err_msix_request;
	}

	rc = request_irq(stdev->msix[stdev->event_irq].vector,
			 switchtec_event_isr, 0,
			 "switchtec_event_isr", stdev);

	if (rc)
		goto err_msix_request;

	dev_dbg(stdev_pdev_dev(stdev), "Using msix interrupts: event_irq=%d\n",
		stdev->event_irq);
	return 0;

err_msix_request:
	pci_disable_msix(pdev);
err_msix_enable:
	kfree(stdev->msix);
	return rc;
}

static void switchtec_deinit_msix_isr(struct switchtec_dev *stdev)
{
	free_irq(stdev->msix[stdev->event_irq].vector, stdev);
	pci_disable_msix(stdev_pdev(stdev));
	kfree(stdev->msix);
}

static int switchtec_init_msi_isr(struct switchtec_dev *stdev)
{
	int rc;
	struct pci_dev *pdev = stdev_pdev(stdev);

	stdev->msix = NULL;

	/* Try to set up msi irq */
	rc = pci_enable_msi_range(pdev, 1, 4);
	if (rc < 0)
		goto err_msi_enable;

	stdev->event_irq = ioread32(&stdev->mmio_part_cfg->vep_vector_number);
	if (stdev->event_irq < 0 || stdev->event_irq >= 4) {
		rc = -EFAULT;
		goto err_msi_request;
	}

	rc = request_irq(pdev->irq + stdev->event_irq, switchtec_event_isr, 0,
			 "switchtec_event_isr", stdev);
	if (rc)
		goto err_msi_request;

	dev_dbg(stdev_pdev_dev(stdev), "Using msi interrupts: event_irq=%d\n",
		stdev->event_irq);
	return 0;

err_msi_request:
	pci_disable_msi(pdev);
err_msi_enable:
	return rc;
}

static void switchtec_deinit_msi_isr(struct switchtec_dev *stdev)
{
	struct pci_dev *pdev = stdev_pdev(stdev);

	free_irq(pdev->irq + stdev->event_irq, stdev);
	pci_disable_msi(pdev);
}

static void switchtec_deinit_isr(struct switchtec_dev *stdev)
{
	if (stdev->msix)
		switchtec_deinit_msix_isr(stdev);
	else
		switchtec_deinit_msi_isr(stdev);
}

static int switchtec_init_isr(struct switchtec_dev *stdev)
{
	int ret;

	ret = switchtec_init_msix_isr(stdev);
	if (ret)
		ret = switchtec_init_msi_isr(stdev);

	return ret;
}

static int switchtec_init_pci(struct switchtec_dev *stdev,
			      struct pci_dev *pdev)
{
	int rc;
	int partition;

	pci_set_drvdata(pdev, stdev);

	rc = pci_enable_device(pdev);
	if (rc)
		goto err_pci_enable;

	rc = pci_request_regions(pdev, KBUILD_MODNAME);
	if (rc)
		goto err_pci_regions;

	pci_set_master(pdev);

	stdev->mmio = pci_iomap(pdev, 0, 0);
	if (!stdev->mmio) {
		rc = -EIO;
		goto err_iomap;
	}

	stdev->mmio_mrpc = stdev->mmio + SWITCHTEC_GAS_MRPC_OFFSET;
	stdev->mmio_sys_info = stdev->mmio + SWITCHTEC_GAS_SYS_INFO_OFFSET;
	stdev->mmio_flash_info = stdev->mmio + SWITCHTEC_GAS_FLASH_INFO_OFFSET;
	stdev->mmio_ntb = stdev->mmio + SWITCHTEC_GAS_NTB_OFFSET;
	partition = ioread8(&stdev->mmio_ntb->partition_id);
	stdev->mmio_part_cfg = stdev->mmio + SWITCHTEC_GAS_PART_CFG_OFFSET +
		sizeof(struct part_cfg_regs) * partition;

	return 0;

err_iomap:
	pci_clear_master(pdev);
	pci_release_regions(pdev);
err_pci_regions:
	pci_disable_device(pdev);
err_pci_enable:
	pci_set_drvdata(pdev, NULL);
	return rc;
}

static void switchtec_deinit_pci(struct switchtec_dev *stdev)
{
	struct pci_dev *pdev = stdev_pdev(stdev);

	pci_iounmap(pdev, stdev->mmio);
	stdev->mmio = NULL;

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int switchtec_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	struct switchtec_dev *stdev;
	int rc;

	stdev = stdev_create(pdev);
	if (!stdev)
		return PTR_ERR(stdev);

	rc = switchtec_init_pci(stdev, pdev);
	if (rc)
		goto err_init_pci;

	rc = switchtec_init_isr(stdev);
	if (rc) {
		dev_err(stdev_pdev_dev(stdev), "failed to init isr.\n");
		goto err_init_isr;
	}

	dev_info(stdev_dev(stdev), "Management device registered.\n");

	return 0;

err_init_isr:
	switchtec_deinit_pci(stdev);
err_init_pci:
	stdev_unregister(stdev);
	return rc;
}

static void switchtec_pci_remove(struct pci_dev *pdev)
{
	struct switchtec_dev *stdev = pci_get_drvdata(pdev);

	switchtec_deinit_isr(stdev);
	switchtec_deinit_pci(stdev);
	stdev_unregister(stdev);
}

#define SWITCHTEC_PCI_DEVICE(device_id) \
	{ \
		.vendor     = MICROSEMI_VENDOR_ID, \
		.device     = device_id, \
		.subvendor  = PCI_ANY_ID, \
		.subdevice  = PCI_ANY_ID, \
		.class      = MICROSEMI_MGMT_CLASSCODE, \
		.class_mask = 0xFFFFFFFF, \
	}, \
	{ \
		.vendor     = MICROSEMI_VENDOR_ID, \
		.device     = device_id, \
		.subvendor  = PCI_ANY_ID, \
		.subdevice  = PCI_ANY_ID, \
		.class      = MICROSEMI_NTB_CLASSCODE, \
		.class_mask = 0xFFFFFFFF, \
	}

static const struct pci_device_id switchtec_pci_tbl[] = {
	SWITCHTEC_PCI_DEVICE(0x8531),  //PFX 24xG3
	SWITCHTEC_PCI_DEVICE(0x8532),  //PFX 32xG3
	SWITCHTEC_PCI_DEVICE(0x8533),  //PFX 48xG3
	SWITCHTEC_PCI_DEVICE(0x8534),  //PFX 64xG3
	SWITCHTEC_PCI_DEVICE(0x8535),  //PFX 80xG3
	SWITCHTEC_PCI_DEVICE(0x8536),  //PFX 96xG3
	SWITCHTEC_PCI_DEVICE(0x8543),  //PSX 48xG3
	SWITCHTEC_PCI_DEVICE(0x8544),  //PSX 64xG3
	SWITCHTEC_PCI_DEVICE(0x8545),  //PSX 80xG3
	SWITCHTEC_PCI_DEVICE(0x8546),  //PSX 96xG3
	{0}
};
MODULE_DEVICE_TABLE(pci, switchtec_pci_tbl);

static struct pci_driver switchtec_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= switchtec_pci_tbl,
	.probe		= switchtec_pci_probe,
	.remove		= switchtec_pci_remove,
};

static int __init switchtec_init(void)
{
	int rc;

	max_devices = max(max_devices, 256);
	rc = alloc_chrdev_region(&switchtec_devt, 0, max_devices,
				 "switchtec");
	if (rc)
		return rc;

	switchtec_class = class_create(THIS_MODULE, "switchtec");
	if (IS_ERR(switchtec_class)) {
		rc = PTR_ERR(switchtec_class);
		goto err_create_class;
	}

	rc = pci_register_driver(&switchtec_pci_driver);
	if (rc)
		goto err_pci_register;

	pr_info(KBUILD_MODNAME ": loaded.\n");

	return 0;

err_pci_register:
	class_destroy(switchtec_class);

err_create_class:
	unregister_chrdev_region(switchtec_devt, max_devices);

	return rc;
}
module_init(switchtec_init);

static void __exit switchtec_exit(void)
{
	pci_unregister_driver(&switchtec_pci_driver);
	class_destroy(switchtec_class);
	unregister_chrdev_region(switchtec_devt, max_devices);
	ida_destroy(&switchtec_minor_ida);

	pr_info(KBUILD_MODNAME ": unloaded.\n");
}
module_exit(switchtec_exit);
