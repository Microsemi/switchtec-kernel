/*
 * Microsemi Switchtec PCIe Driver
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

#ifndef SWITCHTEC_H
#define SWITCHTEC_H

#include <linux/pci.h>

#define MICROSEMI                   0x11f8
#define MICROSEMI_PSX_PM8543        0x8543
#define MICROSEMI_NTB_CLASSCODE     0x068000
#define MICROSEMI_CLASSCODE_MASK    0xFFFFFFFF

enum {
	SWITCHTEC_GAS_MRPC_OFFSET       = 0x0000,
	SWITCHTEC_GAS_TOP_CFG_OFFSET    = 0x1000,
	SWITCHTEC_GAS_SW_EVENT_OFFSET   = 0x1800,
	SWITCHTEC_GAS_PART_CFG_OFFSET   = 0x4000,
	SWITCHTEC_GAS_NTB_OFFSET        = 0x10000,
	SWITCHTEC_GAS_PFF_CSR_OFFSET    = 0x134000,
};

struct mrpc_regs {
	u8 input_data[1024];
	u8 output_data[1024];
	u32 cmd;
	u32 status;
	u32 ret_value;
} __packed;

struct ntb_info_regs {
	u8  partition_count;
	u8  partition_id;
	u16 reserved1;
	u64 ep_map;
	u16 requester_id;
} __packed;

struct part_cfg_regs {
	u32 status;
	u32 state;
	u32 port_cnt;
	u32 usp_port_mode;
	u32 usp_pff_inst_id;
	u32 vep_pff_inst_id;
	u32 dsp_inst_id[47];
	u32 reserved1[11];
	u16 vep_vector_number;
	u16 usp_vector_number;
	u32 port_event_bitmap;
	u32 reserved2[3];
	u32 part_event_summary;
	u32 reserved3[3];
	u32 part_reset_event_hdr;
	u8  part_reset_event_data[20];
	u32 mrpc_completion_hdr;
	u8  mrpc_completion_data[20];
	u32 mrpc_completion_async_hdr;
	u8  mrpc_completion_async_data[20];
	u32 dynamic_part_binding_evt_hdr;
	u8 dynamic_part_binding_evt_data[20];
	u32 reserved4[159];
} __packed;

enum {
	SWITCHTEC_PART_CFG_EVENT_MRPC_CMP = 2,
	SWITCHTEC_PART_CFG_EVENT_MRPC_ASYNC_CMP = 4,
};

struct switchtec_dev {
	struct pci_dev *pdev;
	struct msix_entry *msix;
	struct device *dev;
	struct kref kref;

	unsigned int event_irq;

	void __iomem *mmio;
	struct mrpc_regs __iomem *mmio_mrpc;
	struct ntb_info_regs __iomem *mmio_ntb;
	struct part_cfg_regs __iomem *mmio_part_cfg;
};

#define stdev_pdev(stdev) ((stdev)->pdev)
#define stdev_pdev_dev(stdev) (&stdev_pdev(stdev)->dev)
#define stdev_name(stdev) pci_name(stdev_pdev(stdev))
#define stdev_dev(stdev) (stdev->dev)

#endif
