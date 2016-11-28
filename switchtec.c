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

MODULE_DESCRIPTION("Microsemi Switchtec(tm) PCI-E Management Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Microsemi Corporation");

static int switchtec_major;
static struct class *switchtec_class;
static DEFINE_IDA(switchtec_minor_ida);

static int switchtec_dev_open(struct inode *inode, struct file *filp)
{
	return -ENXIO;
}

static int switchtec_dev_release(struct inode *inode, struct file *filp)
{
	return -ENXIO;
}

static ssize_t switchtec_dev_write(struct file *filp, const char __user *data,
				   size_t size, loff_t *off)
{
	return -ENXIO;
}

static ssize_t switchtec_dev_read(struct file *filp, char __user *data,
				  size_t size, loff_t *off)
{
	return -ENXIO;
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

static void switchtec_mrpc_cmd_done(struct switchtec_dev *stdev)
{

}

static irqreturn_t switchtec_event_isr(int irq, void *dev)
{
	struct switchtec_dev *stdev = dev;
	u32 summary;

	summary = ioread32(&stdev->mmio_part_cfg->part_event_summary);

	if (summary & SWITCHTEC_PART_CFG_EVENT_MRPC_CMP)
		switchtec_mrpc_cmd_done(stdev);
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

	rc = request_irq(stdev->msix[stdev->event_irq].vector,
			 switchtec_event_isr, 0,
			 "switchtec_event_isr", stdev);

	if (rc)
		goto err_msix_request;

	dev_dbg(stdev_dev(stdev), "Using msix interrupts\n");
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

	rc = request_irq(pdev->irq + stdev->event_irq, switchtec_event_isr, 0,
			 "switchtec_event_isr", stdev);
	if (rc)
		goto err_msi_request;

	dev_dbg(stdev_dev(stdev), "Using msi interrupts\n");
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

	stdev->event_irq = ioread32(&stdev->mmio_part_cfg->vep_vector_number);

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

	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static inline void stdev_init_struct(struct switchtec_dev *stdev,
				     struct pci_dev *pdev)
{
	stdev->pdev = pdev;
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

	stdev_init_struct(stdev, pdev);

	rc = switchtec_init_pci(stdev, pdev);
	if (rc)
		goto err_init_pci;

	rc = switchtec_init_isr(stdev);
	if (rc) {
		dev_err(stdev_dev(stdev), "failed to init isr.\n");
		goto err_init_isr;
	}

	dev_info(&pdev->dev, "Management device registered.\n");

	return 0;

err_init_isr:
	switchtec_deinit_pci(stdev);
err_init_pci:
	kfree(stdev);
err_stdev:
	return rc;
}

static void switchtec_pci_remove(struct pci_dev *pdev)
{
	struct switchtec_dev *stdev = pci_get_drvdata(pdev);

	switchtec_deinit_isr(stdev);
	switchtec_deinit_pci(stdev);
	kfree(stdev);
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
	pr_info(KBUILD_MODNAME ": loaded.\n");

	return pci_register_driver(&switchtec_pci_driver);
}
module_init(switchtec_init);

static void __exit switchtec_exit(void)
{
	pci_unregister_driver(&switchtec_pci_driver);

	pr_info(KBUILD_MODNAME ": unloaded.\n");
}
module_exit(switchtec_exit);
