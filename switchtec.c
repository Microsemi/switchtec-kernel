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

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_DESCRIPTION("Microsemi Switchtec(tm) PCI-E Management Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsemi Corporation");

static int switchtec_major;
static struct class *switchtec_class;
static DEFINE_IDA(switchtec_minor_ida);

static int __match_devt(struct device *dev, const void *data)
{
	const dev_t *devt = data;

	return dev->devt == *devt;
}

static struct device *switchtec_dev_find(dev_t dev_t)
{
	return class_find_device(switchtec_class, NULL, &dev_t, __match_devt);
}

struct switchtec_user {
	struct switchtec_dev *stdev;

	enum {
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

static void stuser_free(struct kref *kref)
{
	struct switchtec_user *stuser;
	stuser = container_of(kref, struct switchtec_user, kref);

	kfree(stuser);
}

static void stuser_init(struct switchtec_user *stuser,
			struct switchtec_dev *stdev)
{
	stuser->stdev = stdev;
	kref_init(&stuser->kref);
	INIT_LIST_HEAD(&stuser->list);
}

static void stuser_put(struct switchtec_user *stuser)
{
	kref_put(&stuser->kref, stuser_free);
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

	stuser->state = MRPC_RUNNING;
	stdev->mrpc_busy = 1;
	memcpy_toio(&stdev->mmio_mrpc->input_data,
		    stuser->data, stuser->data_len);
	iowrite32(stuser->cmd, &stdev->mmio_mrpc->cmd);

	stuser->status = ioread32(&stdev->mmio_mrpc->status);
	if (stuser->status != SWITCHTEC_MRPC_STATUS_INPROGRESS)
		mrpc_complete_cmd(stdev);
}

static void mrpc_queue_cmd(struct switchtec_user *stuser)
{
	/* requires the mrpc_mutex to already be held when called */

	struct switchtec_dev *stdev = stuser->stdev;

	kref_get(&stuser->kref);
	stuser->state = MRPC_QUEUED;
	init_completion(&stuser->comp);
	list_add_tail(&stuser->list, &stdev->mrpc_queue);

	mrpc_cmd_submit(stdev);
}

static void mrpc_complete_cmd(struct switchtec_dev *stdev)
{
	/* requires the mrpc_mutex to already be held when called */
	struct switchtec_user *stuser;

	BUG_ON(list_empty(&stdev->mrpc_queue));

	stuser = list_entry(stdev->mrpc_queue.next, struct switchtec_user,
			    list);

	stuser->status = ioread32(&stdev->mmio_mrpc->status);
	if (stuser->status == SWITCHTEC_MRPC_STATUS_INPROGRESS)
		return;

	stuser->state = MRPC_DONE;
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
	mrpc_complete_cmd(stdev);
	mutex_unlock(&stdev->mrpc_mutex);
}

static void stdev_free(struct kref *kref)
{
	struct switchtec_dev *stdev;
	struct switchtec_user *stuser, *temp;

	stdev = container_of(kref, struct switchtec_dev, kref);

	dev_dbg(stdev_dev(stdev), "%s\n", __func__);

	list_for_each_entry_safe(stuser, temp, &stdev->mrpc_queue, list) {
		stuser->status = SWITCHTEC_MRPC_STATUS_INTERRUPTED;
		list_del_init(&stuser->list);
		stuser_put(stuser);
	}

	kfree(stdev);
}

static void stdev_init(struct switchtec_dev *stdev,
		       struct pci_dev *pdev)
{
	stdev->pdev = pdev;
	kref_init(&stdev->kref);
	INIT_LIST_HEAD(&stdev->mrpc_queue);
	mutex_init(&stdev->mrpc_mutex);
	stdev->mrpc_busy = 0;
	INIT_WORK(&stdev->mrpc_work, mrpc_event_work);
}

static void stdev_put(struct switchtec_dev *stdev)
{
	kref_put(&stdev->kref, stdev_free);
}

static int stdev_is_alive(struct switchtec_dev *stdev)
{
	return stdev->mmio != NULL;
}

static int switchtec_dev_open(struct inode *inode, struct file *filp)
{
	struct device *dev;
	struct switchtec_dev *stdev;
	struct switchtec_user *stuser;
	int rc;

	dev = switchtec_dev_find(inode->i_rdev);
	if (!dev)
		return -ENXIO;

	device_lock(dev);
	stdev = dev_get_drvdata(dev);
	if (!stdev) {
		rc = -ENXIO;
		goto err_unlock_exit;
	}

	dev_dbg(stdev_dev(stdev), "%s\n", __func__);
	kref_get(&stdev->kref);

	stuser = kzalloc(sizeof(*stuser), GFP_KERNEL);
	if (!stuser) {
		rc = -ENOMEM;
		goto err_unlock_exit;
	}

	stuser_init(stuser, stdev);
	filp->private_data = stuser;

	device_unlock(dev);
	nonseekable_open(inode, filp);
	return 0;

err_unlock_exit:
	device_unlock(dev);
	put_device(dev);
	return rc;
}

static int switchtec_dev_release(struct inode *inode, struct file *filp)
{
	struct switchtec_user *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;
	struct device *dev = stdev_dev(stdev);

	dev_dbg(dev, "%s\n", __func__);

	stuser_put(stuser);
	stdev_put(stdev);
	put_device(dev);

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
	    size >= sizeof(stuser->cmd) + SWITCHTEC_MRPC_PAYLOAD_SIZE)
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

	rc = wait_for_completion_interruptible(&stuser->comp);
	if (rc < 0)
		return rc;

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
	rc = copy_to_user(data, &stuser->data, size - sizeof(stuser->return_code));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	stuser->state = MRPC_IDLE;

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

static const struct file_operations switchtec_fops = {
	.owner = THIS_MODULE,
	.open = switchtec_dev_open,
	.release = switchtec_dev_release,
	.write = switchtec_dev_write,
	.read = switchtec_dev_read,
};

static int switchtec_register_dev(struct switchtec_dev *stdev)
{
	int rc;
	int minor;
	struct device *dev;
	dev_t devt;

	minor = ida_simple_get(&switchtec_minor_ida, 0, 0,
			       GFP_KERNEL);
	if (minor < 0)
		return minor;

	devt = MKDEV(switchtec_major, minor);
	dev = device_create(switchtec_class, &stdev->pdev->dev,
			    devt, stdev, "switchtec%d", minor);
	if (IS_ERR(dev)) {
		rc = PTR_ERR(dev);
		goto err_create;
	}

	stdev->dev = dev;

	return 0;


err_create:
	ida_simple_remove(&switchtec_minor_ida, minor);

	return rc;
}

static void switchtec_unregister_dev(struct switchtec_dev *stdev)
{
	get_device(stdev_dev(stdev));
	device_unregister(stdev_dev(stdev));
	ida_simple_remove(&switchtec_minor_ida, MINOR(stdev_dev(stdev)->devt));
	put_device(stdev_dev(stdev));
}

static irqreturn_t switchtec_event_isr(int irq, void *dev)
{
	struct switchtec_dev *stdev = dev;
	u32 summary;

	summary = ioread32(&stdev->mmio_part_cfg->part_event_summary);

	if (summary & SWITCHTEC_PART_CFG_EVENT_MRPC_CMP)
		schedule_work(&stdev->mrpc_work);
        else
		dev_dbg(stdev_dev(stdev), "unknown event: %x\n", summary);


	return IRQ_HANDLED;
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
        stdev->mmio_ntb = stdev->mmio + SWITCHTEC_GAS_NTB_OFFSET;
	partition = ioread8(&stdev->mmio_ntb->partition_id);
	stdev->mmio_part_cfg = stdev->mmio + SWITCHTEC_GAS_PART_CFG_OFFSET +
		sizeof(struct part_cfg_regs) * partition;

	return 0;

err_iomap:
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
	int rc, node;

	node = dev_to_node(&pdev->dev);

	stdev = kzalloc_node(sizeof(*stdev), GFP_KERNEL, node);
	if (!stdev) {
		rc = -ENOMEM;
		goto err_stdev;
	}

	stdev_init(stdev, pdev);

	rc = switchtec_init_pci(stdev, pdev);
	if (rc)
		goto err_init_pci;

	rc = switchtec_init_isr(stdev);
	if (rc) {
		dev_err(stdev_pdev_dev(stdev), "failed to init isr.\n");
		goto err_init_isr;
	}

	rc = switchtec_register_dev(stdev);
	if (rc)
		goto err_register_dev;

	dev_info(stdev_dev(stdev), "Management device registered.\n");

	return 0;

err_register_dev:
	switchtec_deinit_isr(stdev);
err_init_isr:
	switchtec_deinit_pci(stdev);
err_init_pci:
	stdev_put(stdev);
err_stdev:
	return rc;
}

static void switchtec_pci_remove(struct pci_dev *pdev)
{
	struct switchtec_dev *stdev = pci_get_drvdata(pdev);

	switchtec_unregister_dev(stdev);
	switchtec_deinit_isr(stdev);
	switchtec_deinit_pci(stdev);
	stdev_put(stdev);
}

static const struct pci_device_id switchtec_pci_tbl[] = {
	{
		.vendor     = MICROSEMI,
		.device     = MICROSEMI_PSX_PM8543,
		.subvendor  = PCI_ANY_ID,
		.subdevice  = PCI_ANY_ID,
		.class      = MICROSEMI_NTB_CLASSCODE,
		.class_mask = MICROSEMI_CLASSCODE_MASK,
	},
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

	rc = register_chrdev(0, "switchtec", &switchtec_fops);
	if (rc < 0)
		return rc;
	switchtec_major = rc;

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
	unregister_chrdev(switchtec_major, "switchtec");

	return rc;
}
module_init(switchtec_init);

static void __exit switchtec_exit(void)
{
	pci_unregister_driver(&switchtec_pci_driver);
	class_destroy(switchtec_class);
	unregister_chrdev(switchtec_major, "switchtec");
	ida_destroy(&switchtec_minor_ida);

	pr_info(KBUILD_MODNAME ": unloaded.\n");
}
module_exit(switchtec_exit);
