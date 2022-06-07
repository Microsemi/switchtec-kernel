/*******************************************************************************
 *   COPYRIGHT (C) 2017 - 2018 CELESTICA, INC. ALL RIGHTS RESERVED.
 * --------------------------------------------------------------------------
 *  This software embodies materials and concepts which are proprietary and
 *  confidential to CELESTICA, Inc.
 *  CELESTICA distributes this software to its customers pursuant to the
 *  terms and conditions of the Software License Agreement
 *  contained in the text file software.lic that is distributed along with
 *  the software. This software can only be utilized if all
 *  terms and conditions of the Software License Agreement are
 *  accepted. If there are any questions, concerns, or if the
 *  Software License Agreement text file, software.lic, is missing please
 *  contact CELESTICA for assistance.
 * --------------------------------------------------------------------------
 ****************************************************************************/

#ifndef __CLS_SG_H__
#define __CLS_SG_H__

#include <linux/semaphore.h>
#include <scsi/sg.h>
#include <linux/version.h>
#include "linux/switchtec.h"
#include "linux/switchtec_ioctl.h"

/*****************************************************************************
 *				DEBUG MACROS
 ****************************************************************************/

#ifndef NTB_EMERG
#define	NTB_EMERG	KERN_EMERG
#endif

#ifndef NTB_ALERT
#define NTB_ALERT	KERN_ALERT
#endif

#ifndef NTB_CRIT
#define NTB_CRIT	KERN_CRIT
#endif

#ifndef NTB_ERR
#define	NTB_ERR		KERN_ERR
#endif

#ifndef NTB_WARNING
#define NTB_WARNING	KERN_WARNING
#endif

#ifndef NTB_NOTICE
#define NTB_NOTICE	KERN_NOTICE
#endif

#ifndef NTB_INFO
#define NTB_INFO	KERN_INFO
#endif

#ifndef NTB_DEBUG
#define NTB_DEBUG	KERN_DEBUG
#endif

#define LOG_EMERG(...)		printk(NTB_EMERG __VA_ARGS__)
#define LOG_ALERT(...)		printk(NTB_ALERT __VA_ARGS__)
#define LOG_CRIT(...)		printk(NTB_CRIT __VA_ARGS__)
#define LOG_ERR(...)		printk(NTB_ERR __VA_ARGS__)
#define LOG_WARNING(...)	printk(NTB_WARNING __VA_ARGS__)

#define LOG_NOTICE(...)		printk(NTB_NOTICE __VA_ARGS__)
#define LOG_INFO(...)		printk(NTB_INFO __VA_ARGS__)
#define LOG_DEBUG(...)		printk(NTB_DEBUG __VA_ARGS__)

/*****************************************************************************
 *				CONVENIENCE MACROS
 ****************************************************************************/
#define DRIVER_VERSION "0.1.3"
#define PERF_OPT   1
#define MEM_COPY   0
 
#define SUCCESS    0
#define ERROR      -1
#define TRUE       1
#define FALSE      0

#define INVALID_PARTITION   8
#define NORMAL_MAPPING      0
#define EXTENDED_MAPPING    1
#define DOUBLE_WORD_SIZE    4
#define WORD_SIZE           2
#define BYTE_SIZE           1
#define MEM_SIZE            (1024 * 1024)
#define MSECS_PER_SEC       1000
#define BITS_PER_BYTE       8

#define LOCAL_CONFIG_ACCESS_BAR     PCI_BAR_0
#define REMOTE_CONFIG_ACCESS_BAR    PCI_BAR_4
#define PCIE_CONFIG_SPACE_SIZE      (4 * 1024)
#define MEMORY_PER_EP               (2 * 1024 * 1024)
#define HIGH_ADDR_shift             32
#define BIT_MASK_32                 0xFFFFFFFF
#define BIT_MASK_64                 0xFFFFFFFFFFFFFFFF

#define FLD_GET(f, v)    (((v) & f ## _mask) >> f ## _shift)
#define FLD_SET(f, v)    (((v) << f ## _shift) & f ## _mask)

/*
 * Frame retry interval
 */
#define RETRY_FREQ       ((HZ / 100) ? (HZ / 100) : 1)

#define ENDIAN_SWAP_8_BYTE(_i)  \
        ((((((u64)(_i)) >>  0) & (u64)0xff) << 56) | \
         (((((u64)(_i)) >>  8) & (u64)0xff) << 48) | \
         (((((u64)(_i)) >> 16) & (u64)0xff) << 40) | \
         (((((u64)(_i)) >> 24) & (u64)0xff) << 32) | \
         (((((u64)(_i)) >> 32) & (u64)0xff) << 24) | \
         (((((u64)(_i)) >> 40) & (u64)0xff) << 16) | \
         (((((u64)(_i)) >> 48) & (u64)0xff) <<  8) | \
         (((((u64)(_i)) >> 56) & (u64)0xff) <<  0))

#define ENDIAN_SWAP_4_BYTE(_i)  \
        (((((u32)(_i)) & 0xff000000) >> 24) |  \
	 ((((u32)(_i)) & 0x00ff0000) >>  8) |   \
	 ((((u32)(_i)) & 0x0000ff00) <<  8) |   \
	 ((((u32)(_i)) & 0x000000ff) << 24))

#define ENDIAN_SWAP_2_BYTE(_i)  \
	(((((u16)(_i)) & 0xff00) >> 8) |  \
	 ((((u16)(_i)) & 0x00ff) << 8))

#define LE_TO_BE_64(_i)     ENDIAN_SWAP_8_BYTE((_i))
#define LE_TO_BE_32(_i)     ENDIAN_SWAP_4_BYTE((_i))
#define LE_TO_BE_16(_i)     ENDIAN_SWAP_2_BYTE((_i))

#define BE_TO_LE_64(_i)     ENDIAN_SWAP_8_BYTE((_i))
#define BE_TO_LE_32(_i)     ENDIAN_SWAP_4_BYTE((_i))
#define BE_TO_LE_16(_i)     ENDIAN_SWAP_2_BYTE((_i))


/*****************************************************************************
 *				LIMIT MACROS
 ****************************************************************************/

#define DBELL_BITS_PER_PART    4
#define DBELL_BIT_MASK         0xF
#define INMSG_BIT_MASK         0x000F0000
#define OUTMSG_BIT_MASK        0x0000000F

/* 
 * Totally 4KB for base layer data 
 * APERTURE_PRIV_MAX = 4KB - (sizeof(remote_event_count) + sizeof(local_event_count)) 
 */
#define APERTURE_PRIV_MAX      4047   
#define MSGREG_RETRY_MAX       5000
#define SMALL_FRAME_SIZE       32
#define SYSTEM_ID_MAX          16
#define DEV_NAME_MAX           32
#define MT_ENTRY_MAX           128  /* ID mapping table, max entry number is 128 */
#define AT_ENTRY_MAX           512  /* address translation LUT table, max entry number is 512 */
#define AT_CFG_GROUP_ENTRY_MAX 32   /* address translation config group, mas entry number is 32 */
#define MAX_REQUESTS           1000
#define PCI_NUM_BARS           6
#define IPC_MSG_MAX            4
#define IPC_MAX                64
#define MSG_MAX                4
#define NTB_MAX                16  /* driver supports IPC among up to 16 hosts */
#define SWITCH_PORT_MAX        48  /* there are maximum 48 ports in switch  */

#define MAX_MSIX_NUM_VECTOR    4
#define msix_table_size(control)	((control & PCI_MSIX_FLAGS_QSIZE)+1)

#define BUF_POOL_MAX           6
#define BUF_CHUNK_MAX          2
#define HUGE_POOL_SIZE         (1024 * 1024)
#define LARGE_POOL_SIZE        (512 * 1024)
#define BIG_POOL_SIZE          (256 * 1024)
#define MEDIUM_POOL_SIZE       (128 * 1024)
#define SMALL_POOL_SIZE        (64 * 1024)
#define TINY_POOL_SIZE         (32 * 1024)

#define MTBL_ENTRY_MAX         254//64
#define MTBL_ENTRIES_PER_PART  254//(MTBL_ENTRY_MAX / NTB_MAX)
#define MTBL_ENTRIES_MASK      0xFF

#define MIN_NT_WINDOW          4096

#define MAX_DEV_NUM		12

/*****************************************************************************
 *				LIMIT MACROS
 ****************************************************************************/

#define PMC_DMA_CHAN_MAX    2
#define IOAT_DMA_CHAN_MAX     2

/*****************************************************************************
 *		PCIe DEVICE NAME, VENDOR & DEVICE ID MACROS
 ****************************************************************************/

#define PMC_SW_DEV_NAME            "pmc-psx"
#define PMC_SW_DEV_MAJOR           300
#define PMC_SW_NTB_IF              "pmc-ntb"
#define PMC_SW_VID                 0x11F8
#define PMC_SW_FAKE_NTB_DEV_ID     0xBEEF /* Device ID */
#define PMC_SW_RIVISION            (0x1)
#define PMC_SW_NTB_TYPE_ID         (0x30)
#define PMC_SW_SUBVID              PCI_ANY_ID 
#define PMC_SW_SUBDID              PCI_ANY_ID
#define PMC_SW_NTB_CLASSCODE       0x068000
#define PMC_SW_MGMT_CLASSCODE      0x058000
#define PMC_SW_CLASSCODE_shift     8
#define PMC_SW_CLASSCODE_mask      0xFFFFFFFF

/* PCIe Switch endpoint device ID */
#define PMC_PFX_PM8530             0x8530  //Reserved
#define PMC_PFX_PM8531             0x8531  //PFX 24xG3
#define PMC_PFX_PM8532             0x8532  //PFX 32xG3
#define PMC_PFX_PM8533             0x8533  //PFX 48xG3
#define PMC_PFX_PM8534             0x8534  //PFX 64xG3
#define PMC_PFX_PM8535             0x8535  //PFX 80xG3
#define PMC_PFX_PM8536             0x8536  //PFX 96xG3
#define PMC_PFX_PM8537             0x8537  //Reserved
#define PMC_PSX_PM8554             0x8554  //Reserved
#define PMC_PSX_PM8555             0x8555  //Reserved
#define PMC_PSX_PM8556             0x8556  //Reserved
#define PMC_PSX_PM8543             0x8543  //PSX 48xG3
#define PMC_PSX_PM8544             0x8544  //PSX 64xG3
#define PMC_PSX_PM8545             0x8545  //PSX 80xG3
#define PMC_PSX_PM8546             0x8546  //PSX 96xG3
#define PMC_PSX_PM8547             0x8547  //Reserved

#define PCI_CFG_CLASS_CODE_off  	0x0B
#define PCI_CFG_SUB_CLASS_CODE_off  0x0A


/*****************************************************************************
 *				NTB ENDPOINT STATE MACROS
 ****************************************************************************/

/*                    Driver state machine
 *                    ====================      
 *                          
 *                                          SCE                    
 *                                         ^   ^
 *                                        /     \         -------------------------
 *                                       /       \    --->|                       |
 *                                      /         \  |    | Start request & reply |
 *                     SMRS -------> SMD-->SMCE-->SME     |       handshake       |
 *                     ^   ^         ^               ^    | Map request & reply   |
 *                     |    \        |               |    |       handshake       | 
 *                     |     \       |               -----|                       |
 *       SSRS -----> SID --> SMS --> SMSD                 -------------------------
 *       ^   ^         ^                          
 *      /     \        |                          
 *     /       \       |                                 
 *    SD  --> SSS --> SSSD                        
 *     ^
 *     |
 *  ___|___
 * |       |  
 * | Start |
 * |_______|
 *
 * */


/* [SD]: Down state. Initial state of the driver. No operations. */

#define STATE_DOWN              0x00000001  

/* [SSS]: Driver moves to SSD after sending start request message to remote EP. 
 *        It waits for either start reply or start request from remote EP. */

#define STATE_START_SEND        0x00000002  

/* [SSRS]: Driver moves to SSRS after receiving start request message and at the 
 *         same time is sends start request message to remote EP. It waits for 
 *         start reply from remote EP */

#define STATE_START_RECV_SEND   0x00000004

/* [SSSD]: Driver moves to SSSD after getting start reply from remote EP. It 
 *         waits for start request message from remote EP */

#define STATE_START_SEND_DONE   0x00000008

/* [SID]: Driver moves to SID after completing the start request and start 
 *        reply handshake */

#define STATE_INIT_DONE         0x00000010

/* [SMS]: Driver moves to SMS after sending map request message to remote 
 *        EP. It waits for either map reply or map request from the remote EP. */

#define STATE_MAP_SEND          0x00000020

/* [SMRS]: Driver moves to SMRS after receiving map request from remote EP. It 
 *         sends map request and waits for map reply from remote EP */

#define STATE_MAP_RECV_SEND     0x00000040

/* [SMSD]: Driver moves to SMSD after getting map reply from remote EP. It waits 
 *         for map request from remote EP. */

#define STATE_MAP_SEND_DONE     0x00000080

/* [SMD]: Driver moves to SMD after completing the map request and map reply 
 *        handshake */

#define STATE_MAP_DONE          0x00000100

/* [SMCE]: (1) Driver running on RP moves to this state after receiving 
 *             IPC_CMD_MAP_CONFIG_EXT message from an EP. It replies to EP 
 *             with the confic space enumerated address of remote EP. 
 *         (2) Driver running on EP moves to this state after sending 
 *             IPC_CMD_MAP_CONFIG_EXT message. */ 

#define STATE_MAP_CONFIG_EXT_SEND    0x00000200

#define STATE_MAP_CONFIG_EXT_RECV    0x00000400

#define STATE_MAP_CONFIG_EXT_DONE 0x00000800

/* [SME]: (1) Driver running on RP moves to this state after receiving 
 *            IPC_CMD_MAP_EXT message from an EP. It sets the LUT of remote 
 *            EP with the address obtained from this message and sends the 
 *            enumerated address of this mapping to the EP. 
 *        (2) Driver running on EP moves to this state after receiving the 
 *            IPC_CMD_MAP_CONFIG_EXT reply message from RP. The regular start 
 *            and map state machine is triggered here by the EP with remote 
 *            EPs. */

#define STATE_MAP_EXT           0x00001000

/* [SCE]: Driver moves to SCE in two different ways. 
 *        (1) If the driver is running in "Single PMC" or "Punch-through" 
 *            scenarios, it moves to SCE immediately after the handshake of 
 *            map requests & replies. 
 *        (2) If the driver is running in "System interconnect" scenario, 
 *            it moves to SCE after "extended map config" and 
 *            "extended map" exchanges. */       

#define STATE_CONN_EST         0x00002000

/*****************************************************************************
 *			PCIe SWITCH's vEP(NTB/MGMT) ENDPOINT REGISTERS
 ****************************************************************************/

#define PSX_REG_PCICMD_off              0x004
#define PSX_REG_PCICMD_IOAE_val         0x0001
#define PSX_REG_PCICMD_IOAE_mask        0x0001
#define PSX_REG_PCICMD_MAE_val          0x0002
#define PSX_REG_PCICMD_MAE_mask         0x0002
#define PSX_REG_PCICMD_BME_val          0x0004
#define PSX_REG_PCICMD_BME_mask         0x0004
#define PSX_REG_PCICMD_INTXD_val        0x0400
#define PSX_REG_PCICMD_INTXD_mask       0x0400

#define PSX_REG_PCI_HEADER_TYPE_off     0x0E

/* Need to find the offset according to PCIe spec */
#define PSX_REG_PTCCTL1_TYPE0_val      0x0      
#define PSX_REG_PTCCTL1_TYPE1_val      0x1      
#define PSX_REG_PTCCTL1_READ_OP_val    0x0      
#define PSX_REG_PTCCTL1_WRITE_OP_val   0x1      
#define PSX_REG_PTCCTL1_OP_shift       1      
#define PSX_REG_PTCSTS_BUSY_mask       0x00000001        
#define PSX_REG_PTCSTS_DONE_mask       0x00000002        
#define PSX_REG_PTCSTS_STATUS_mask     0x0000001C        

/*
 * PCIE link capability, control and status register set 1
 */
#define PSX_REG_PCIE_LCAP_off           0x0000004C
#define PSX_REG_PCIE_LCTL_off           0x00000050
#define PSX_REG_PCIE_LCTL_NLW_mask      0x03F00000
#define PSX_REG_PCIE_LSTS_off           0x00000052
#define PSX_REG_PCIE_LCAP_PORT_shift    24
#define PSX_REG_PCIE_LCAP_PORT_mask     0xFF000000

/*
 * PCIE link capability, control and status register set 2
 */
#define PSX_REG_PCIE_LCAP2_off          0x0000006C
#define PSX_REG_PCIE_LCTL2_off          0x00000070
#define PSX_REG_PCIE_LSTS2_off          0x00000072

/*
 * PCIE device capability, control and status register set 1
 */
#define PSX_REG_PCIE_DCAP_off           0x00000044
#define PSX_REG_PCIE_DCTL_off           0x00000048
#define PSX_REG_PCIE_DSTS_off           0x0000004A
#define PSX_REG_PCIE_DCAP_MPLOAD_shift  0
#define PSX_REG_PCIE_DCAP_MPLOAD_mask   0x00000007
#define PSX_REG_PCIE_DCTL_MPS_shift     5
#define PSX_REG_PCIE_DCTL_MPS_mask      0x000000E0
#define PSX_REG_PCIE_DCTL_MRRS_shift    12
#define PSX_REG_PCIE_DCTL_MRRS_mask     0x00007000

/*
 * PCIE device capability, control and status register set 2
 */
#define PSX_REG_PCIE_DCAP2_off          0x00000064
#define PSX_REG_PCIE_DCTL2_off          0x00000068
#define PSX_REG_PCIE_DSTS2_off          0x0000006A

/*
* BAR0 Memory space registers layout
*/
#define GAS_MRPC_off                    0x0000   //4K
#define GAS_TOP_CFG_off             	0x1000   //2k
#define GAS_SW_EVENT_off                0x1800   //2k
#define GAS_RESERVE_off                 0x2000   //8K reserved
#define GAS_PART_CFG_off                0x4000   //48 x 1K
#define GAS_NTB_off       			    0x10000  //NTB sector offset starting from 64k
#define GAS_P2P_CSR_off                 0x134000  

/* MRPC Region  */
#define GAS_MRPC_INPUT_DATA_off         GAS_MRPC_off
#define GAS_MRPC_OUTPUT_DATA_off        0x0400
#define GAS_MRPC_COMMAND_off            0x0800
#define GAS_MRPC_STATUS_off             0x0804
#define GAS_MRPC_CMD_RETURN_VALUE_off   0x0808

#define MRPC_STAT_INPROGRESS      		0x01
#define MRPC_STAT_DONE      			0x02


/* Switch Topology Setup */
#define TOP_PART_CNT                    0x1007
#define TOP_LOCAL_PART_ID               0x1008


/* Switch and FW event Region  */
#define SW_EVT_CTR_off                       			GAS_SW_EVENT_off
#define SW_EVT_PART_BITMAP_off               			0x1810
#define SW_EVT_GBL_SUMY_off               				0x1820
#define SW_EVT_GBL_HEADER_off(slot)             		(0x1830 + 0x18*(slot))
#define SW_EVT_GBL_DATA_off(slot)               		(0x1834 + 0x18*(slot))
#define SW_EVT_GBL_STACK_ERR_DATA_off            		0x1834
#define SW_EVT_GBL_PPU_ERR_DATA_off             		0x184C
#define SW_EVT_GBL_ISP_ERR_DATA_off             		0x1864
#define SW_EVT_GBL_SYS_RESET_DATA_off            		0x187C
#define SW_EVT_GBL_EXCEPT_DATA_off               		0x1894
#define SW_EVT_GBL_NMI_DATA_off                  		0x18AC
#define SW_EVT_GBL_NON_FATAL_ERR_DATA_off        		0x18C4
#define SW_EVT_GBL_FATAL_ERR_DATA_off            		0x18DC
#define SW_EVT_GBL_TWI_MRPC_CMP_DATA_off         		0x18F4
#define SW_EVT_GBL_TWI_MRPC_ASYNC_CMP_DATA_off          0x190C
#define SW_EVT_GBL_CLI_MRPC_CMP_DATA_off         		0x1824
#define SW_EVT_GBL_CLI_MRPC_ASYNC_CMP_DATA_off          0x193C
#define SW_EVT_PART_MSI_VECTOR_off(part_id)  			(0x4100 + (part_id) * 0x400)
#define SW_EVT_PART_LGL_PORT_BITMAP_off(part_id)   		(0x4104 + (part_id) * 0x400)
#define SW_EVT_PART_SUMY_off(part_id)         			(0x4114 + (part_id) * 0x400)
#define SW_EVT_PART_HEADER_off(part_id, slot) 			(0x4124 + (part_id) * 0x400 + (slot) * 0x18)
#define SW_EVT_PART_DATA_off(part_id, slot)   			(0x4128 + (part_id) * 0x400 + (slot) * 0x18)
#define SW_EVT_PART_RESET_off(part_id)        			(0x4128 + (part_id) * 0x400)
#define SW_EVT_PART_MRPC_SYNC_CMP_off(part_id)      	(0x4140 + (part_id) * 0x400)
#define SW_EVT_PART_MRPC_ASYNC_CMP_off(part_id)     	(0x4158 + (part_id) * 0x400)
#define SW_EVT_PORT_SUMY_off(inst_id)              		(0x134C00 + (inst_id) * 0x1000)
#define SW_EVT_PORT_HEADER_off(inst_id, slot)      		(0x134C10 + (inst_id) * 0x1000 + (slot) * 0x18)
#define SW_EVT_PORT_DATA_off(inst_id, slot)        		(0x134C14 + (inst_id) * 0x1000 + (slot) * 0x18)
#define SW_EVT_PORT_P2P_AER_DATA_off(inst_id)           (0x134C14 + (inst_id) * 0x1000)
#define SW_EVT_PORT_VEP_AER_DATA_off(inst_id)           (0x134C2C + (inst_id) * 0x1000)
#define SW_EVT_PORT_DPC_DATA_off(inst_id)               (0x134C44 + (inst_id) * 0x1000)
#define SW_EVT_PORT_CTS_DATA_off(inst_id)               (0x134C5C + (inst_id) * 0x1000)
#define SW_EVT_PORT_UEC_DATA_off(inst_id)               (0x134C74 + (inst_id) * 0x1000)
#define SW_EVT_PORT_HP_DATA_off(inst_id)                (0x134C8C + (inst_id) * 0x1000)
#define SW_EVT_PORT_IN_ERR_DATA_off(inst_id)            (0x134CA4 + (inst_id) * 0x1000)
#define SW_EVT_PORT_THRESHOLD_DATA_off(inst_id)         (0x134CBC + (inst_id) * 0x1000)
#define SW_EVT_PORT_PWR_DATA_off(inst_id)               (0x134CD4 + (inst_id) * 0x1000)
#define SW_EVT_PORT_TLP_THROT_DATA_off(inst_id)         (0x134CEC + (inst_id) * 0x1000)
#define SW_EVT_PORT_FORCE_SP_DATA_off(inst_id)          (0x134D04 + (inst_id) * 0x1000)
#define SW_EVT_PORT_CREDIT_OUT_DATA_off(inst_id)        (0x134D1C + (inst_id) * 0x1000)

#define SW_EVT_GBL_HEADER_SIZE            12
#define SW_EVT_PART_MRPC_CMP_mask         0x02
#define SW_EVT_PART_MRPC_ASYNC_CMP_mask   0x04
#define SW_EVT_PART_MRPC_CMP_SLOT        	1
#define SW_EVT_PART_MRPC_ASYNC_CMP_SLOT     2


/* Partition configuration region */
#define PART_CFG_TABLE_SIZE              			(1024)
#define PART_CFG_STATUS_off(part_id)     			(0x00 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_STATE_off(part_id)               	(0x04 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_P2P_CNT_off(part_id)             	(0x08 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_USP_PORT_MODE_off(part_id)       	(0x0C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_USP_PFF_INST_ID_off(part_id)     	(0x10 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_VEP_PFF_INST_ID_off(part_id)     	(0x14 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_00_INST_ID_off(part_id)      	(0x18 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_01_INST_ID_off(part_id)      	(0x1C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_02_INST_ID_off(part_id)      	(0x20 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_03_INST_ID_off(part_id)      	(0x24 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_04_INST_ID_off(part_id)      	(0x28 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_05_INST_ID_off(part_id)      	(0x2C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_06_INST_ID_off(part_id)      	(0x30 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_07_INST_ID_off(part_id)      	(0x34 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_08_INST_ID_off(part_id)      	(0x38 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_09_INST_ID_off(part_id)      	(0x3C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_10_INST_ID_off(part_id)      	(0x40 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_11_INST_ID_off(part_id)      	(0x44 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_12_INST_ID_off(part_id)      	(0x48 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_13_INST_ID_off(part_id)      	(0x4C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_14_INST_ID_off(part_id)      	(0x50 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_15_INST_ID_off(part_id)      	(0x54 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_16_INST_ID_off(part_id)      	(0x58 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_17_INST_ID_off(part_id)      	(0x5C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_18_INST_ID_off(part_id)      	(0x60 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_19_INST_ID_off(part_id)      	(0x64 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_20_INST_ID_off(part_id)      	(0x68 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_21_INST_ID_off(part_id)      	(0x6C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_22_INST_ID_off(part_id)      	(0x70 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_23_INST_ID_off(part_id)      	(0x74 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_25_INST_ID_off(part_id)      	(0x7C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_26_INST_ID_off(part_id)      	(0x80 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_27_INST_ID_off(part_id)      	(0x84 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_28_INST_ID_off(part_id)      	(0x88 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_29_INST_ID_off(part_id)      	(0x8C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_30_INST_ID_off(part_id)      	(0x90 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_31_INST_ID_off(part_id)      	(0x94 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_33_INST_ID_off(part_id)      	(0x9C + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_34_INST_ID_off(part_id)      	(0xA0 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_35_INST_ID_off(part_id)      	(0xA4 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_36_INST_ID_off(part_id)      	(0xA8 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_37_INST_ID_off(part_id)      	(0xAC + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_38_INST_ID_off(part_id)      	(0xB0 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_39_INST_ID_off(part_id)      	(0xB4 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_40_INST_ID_off(part_id)      	(0xB8 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_41_INST_ID_off(part_id)      	(0xBC + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_42_INST_ID_off(part_id)      	(0xC0 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_43_INST_ID_off(part_id)      	(0xC4 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_44_INST_ID_off(part_id)      	(0xC8 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_45_INST_ID_off(part_id)      	(0xCC + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_46_INST_ID_off(part_id)      	(0xD0 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)
#define PART_CFG_DSP_47_INST_ID_off(part_id)      	(0xD4 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)

#define PART_CFG_MSI_VECTOR_off(part_id)      	    (0x100 + (part_id) * PART_CFG_TABLE_SIZE + GAS_PART_CFG_off)

#define INVALID_INSTANCE_ID             0xFFFFFFFF

/* NTB Region */
#define NTB_REG_CTL_HDR_off  			GAS_NTB_off
#define NTB_CTL_HEADER_SIZE         	0x4000      //16K
#define NTB_CTL_CFG_PART_SIZE       	0x2000      //8K 
#define NTB_HW_REG_PART_SIZE            0x4000      //16K
#define NTB_REG_CTL_CFG_TBL_HDR_off(x) 	(NTB_REG_CTL_HDR_off + NTB_CTL_HEADER_SIZE + (x)*NTB_CTL_CFG_PART_SIZE) // NTB_REG_CTL_HDR_off + 16K, x means partition id
#define NTB_HW_REG_off					(NTB_REG_CTL_HDR_off + 0x64000 + 0x1000) // NTB_REG_CTL_HDR_off + 400K+ 4K reserved by HW

/*
* NT control header registers
*/
#define NTB_REG_PART_ID_CNT_off         NTB_REG_CTL_HDR_off
#define NTB_REG_PART_MAP_LOW_off        (NTB_REG_CTL_HDR_off + 4)
#define NTB_REG_PART_MAP_HIGH_off       (NTB_REG_CTL_HDR_off + 8)
#define NTB_REG_REQUEST_ID_off          (NTB_REG_CTL_HDR_off + 12)
#define NTB_REG_BDF_mask                0x0000FFFF
#define NTB_REG_FUN_mask                0x00000007
#define NTB_REG_DEV_mask                0x000000F8
#define NTB_REG_DEV_shift               3
#define NTB_REG_BUS_mask                0x0000FF00
#define NTB_REG_BUS_shift               8
#define NTB_REG_PART_ID_mask            0x0000FF00
#define NTB_REG_PART_CNT_mask           0x000000FF
#define NTB_REG_PART_ID_shift           8

/*
* Local NT control configuration table of local partition
*/
/* 
* NT control configuration table header 
* x means parition ID number
*/
#define NTB_REG_PART_STS_off(x)              	NTB_REG_CTL_CFG_TBL_HDR_off(x)
#define NTB_REG_PART_OPT_off(x)              	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 4)
#define NTB_REG_PART_CTL_off(x)                 (NTB_REG_CTL_CFG_TBL_HDR_off(x) + 8)
#define NTB_REG_PART_BARSETUP_INFO_off(x)       (NTB_REG_CTL_CFG_TBL_HDR_off(x) + 12)
#define NTB_REG_PART_BARSETUP_CFG_ERR_off(x)   	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 16)
#define NTB_REG_PART_LUT_INFO_off(x)           	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 20)
#define NTB_REG_PART_LUT_CFG_ERR_off(x)        	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 24)
#define NTB_REG_PART_ID_TABLE_INFO_off(x)      	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 28)
#define NTB_REG_PART_ID_TABLE_ERR_off(x)       	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + 32)

#define NTB_REG_NT_STATUS_mask               0x0000FFFF
#define NTB_REG_LOCK_BY_PART_ID_mask         0x00FF0000
#define NTB_REG_LOCK_BY_PART_ID_shift        16
#define NTB_REG_LOCKED_PART_ID_mask          0xFF000000
#define NTB_REG_LOCKED_PART_ID_shift         24

/*  control configuration table lock status */
#define NT_CFG_STS_UNLOCKED           0x0
#define NT_CFG_STS_LOCKED_BY_LOCAL    0x1
#define NT_CFG_STS_LOCKED_BY_REMOTE   0x2
#define NT_CFG_STS_UNKOWN             0x3

/* NT function operation  */
#define NT_OPT_NO        0x0                    
#define NT_OPT_LOCK      0x1
#define NT_OPT_CFG_HW    0x2
#define NT_OPT_RESET     0x3
#define NT_OPT_UNKNOW    0x4
//#define NT_OPT_RESUME    0x5
//#define NT_OPT_CFM_ERR   0x6

/* NT  function status */
#define NT_STS_UNINITIALIZED    0x0
#define NT_STS_READY            0x1
#define NT_STS_LOCKED           0x2
//#define NT_STS_RUN              0x3
//#define NT_STS_UNKNOWN          0x4

/* 
* BARSETUP registers
* x means parition ID number, y means BARSETUP register offset
*/
#define BARSETUP_SUB_WIN_LUT_BASE_NUM_POS_TYPE(x, y)  		(NTB_REG_CTL_CFG_TBL_HDR_off(x) + y) 
#define BARSETUP_DIR_WIN_SIZE_XLATE_POS(x, y) 		   		(NTB_REG_CTL_CFG_TBL_HDR_off(x) + y + 4)
#define BARSETUP_DIR_WIN_XLATE_LOW_TPART(x, y)    			(NTB_REG_CTL_CFG_TBL_HDR_off(x) + y + 8)
#define BARSETUP_DIR_WIN_XLATE_HIGH(x, y)                 	(NTB_REG_CTL_CFG_TBL_HDR_off(x) + y + 12)

#define NTB_REG_BARSETUP_V_value            0x00000001
#define NTB_REG_BARSETUP_SIZE               (16)
#define NTB_REG_SUB_LUT_BASE_shift          (23)
#define NTB_REG_SUB_WIN_NUM_shift           (14)
#define NTB_REG_SUB_WIN_XLATE_POS_shift     (8)
#define NTB_REG_DIR_CNS_shift               (8)
#define NTB_REG_DIR_CAT_shift               (7)
#define NTB_WIN_TYPE_DIR                    0x10
#define NTB_WIN_TYPE_LUT                    0x20


/* NT Multicast configuration registers */
//#define NTB_REG_MULTCAST_TBL_off        0x1100 //(NTB_REG_CTL_CFG_TBL_HDR_off + 256)


/* 
* NT ID mapping table 
* x means parition ID number, y means ID mapping table register offset
*/
#define NTB_REG_ID_MAP_TBL_ENTRY(x, y)     (NTB_REG_CTL_CFG_TBL_HDR_off(x) + y)    
#define NTB_REG_ID_MAP_TBLE_V_value     0x00000001
#define NTB_REG_ID_BDF_shift            (16)
#define NTB_REG_ID_RNS_shift            (11)
#define NTB_REG_ID_CNS_shift            (10)
#define NTB_REG_ID_ATP_shift            (9)
#define NTB_REG_ID_TAG_shift            (1)
#define NTB_REG_ID_ENTRY_SIZE           (4)
#define NTB_MAX_ID_ENTRY     			(248)


/* 
* NT sub window configuration table 
* x means parition ID number, y means LUT sub window table register offset
*/
#define NTB_REG_SUB_WIN_XLAT_BASE_LOW_TGT_V(x, y)     (NTB_REG_CTL_CFG_TBL_HDR_off(x) + y)
#define NTB_REG_SUB_WIN_XLAT_BASE_HIGH(x, y)          (NTB_REG_CTL_CFG_TBL_HDR_off(x) + y + 4)

//#define NTB_REG_LUT_ENTRY_NUM_mask          0x0000FFFF
#define NTB_REG_XLAT_BASE_LOW_mask          0xFFFFF000
#define NTB_REG_XLAT_BASE_LOW_shift      	(12)
#define NTB_REG_SUB_WIN_TBL_V_value         0x00000001
#define NTB_REG_SUB_LUT_ENTRY_SIZE          (8)
#define NTB_MAX_LUT_ENTRY   				(512)
#define NTB_REG_SUB_WIN_CNS_shift           (8)
#define NTB_REG_SUB_WIN_CAT_shift           (7)
#define NTB_REG_SUB_WIN_TPART_shift         (1)


/* Remote NT control configuration table base address*/
#define NTB_REG_REMOTE_CTL_CFG_TABLE_BASE 	0x3000
#define NTB_CTL_CFG_TABLE_SIZE            	0x2000

/*
*  NTB message/doorbell/interrupt registers in BAR memory space.
*  The first 4KB sector is resversed.
*/

/*
* NTB inboud/outbound doorbell status and mask registers.
* x means parition ID number
*/
#define NTB_REG_OBDB_SET_off(x)        (NTB_HW_REG_off + NTB_HW_REG_PART_SIZE * x)
#define NTB_REG_OBDB_MSK_off(x)        (NTB_HW_REG_off + 0x08 + NTB_HW_REG_PART_SIZE * x)
#define NTB_REG_IBDB_STS_off(x)        (NTB_HW_REG_off + 0x10 + NTB_HW_REG_PART_SIZE * x)
#define NTB_REG_IBDB_MSK_off(x)        (NTB_HW_REG_off + 0x18 + NTB_HW_REG_PART_SIZE * x)

/*
* NTB inboud/outbound message status, mask, mapping, source partition registers.
*/
/* outbound -> inbound message mapping registers */
#define NTB_REG_OBMSG0_MAP_off         (NTB_HW_REG_off + 0x60)
#define NTB_REG_OBMSG1_MAP_off         (NTB_HW_REG_off + 0x61)
#define NTB_REG_OBMSG2_MAP_off         (NTB_HW_REG_off + 0x62)
#define NTB_REG_OBMSG3_MAP_off         (NTB_HW_REG_off + 0x63)
#define NTB_REG_DST_PART_shift         2


/* outbound message and status registers */
#define NTB_REG_OBMSG0_off           (NTB_HW_REG_off + 0x68)
#define NTB_REG_OBMSG0_STS_off       (NTB_HW_REG_off + 0x6C)
#define NTB_REG_OBMSG1_off           (NTB_HW_REG_off + 0x70)
#define NTB_REG_OBMSG1_STS_off       (NTB_HW_REG_off + 0x74)
#define NTB_REG_OBMSG2_off           (NTB_HW_REG_off + 0x78)
#define NTB_REG_OBMSG2_STS_off       (NTB_HW_REG_off + 0x7C)
#define NTB_REG_OBMSG3_off           (NTB_HW_REG_off + 0x80)
#define NTB_REG_OBMSG3_STS_off       (NTB_HW_REG_off + 0x84)
#define NTB_REG_OBMSG_STS_mask       0x01


/* inbound message, status, and source partition registers */
#define NTB_REG_IBMSG0_off            (NTB_HW_REG_off + 0x88)
#define NTB_REG_IBMSG0_STS_MSK_SP_off (NTB_HW_REG_off + 0x8C)
#define NTB_REG_IBMSG0_STS_off        (NTB_HW_REG_off + 0x8C)
#define NTB_REG_IBMSG0_MSK_off        (NTB_HW_REG_off + 0x8D)
#define NTB_REG_IBMSG0_SP_off         (NTB_HW_REG_off + 0x8E)

#define NTB_REG_IBMSG1_off            (NTB_HW_REG_off + 0x90)
#define NTB_REG_IBMSG1_STS_MSK_SP_off (NTB_HW_REG_off + 0x94)
#define NTB_REG_IBMSG1_STS_off        (NTB_HW_REG_off + 0x94)
#define NTB_REG_IBMSG1_MSK_off        (NTB_HW_REG_off + 0x95)
#define NTB_REG_IBMSG1_SP_off         (NTB_HW_REG_off + 0x96)

#define NTB_REG_IBMSG2_off            (NTB_HW_REG_off + 0x98)
#define NTB_REG_IBMSG2_STS_MSK_SP_off (NTB_HW_REG_off + 0x9C)
#define NTB_REG_IBMSG2_STS_off        (NTB_HW_REG_off + 0x9C)
#define NTB_REG_IBMSG2_MSK_off        (NTB_HW_REG_off + 0x9D)
#define NTB_REG_IBMSG2_SP_off         (NTB_HW_REG_off + 0x9E)

#define NTB_REG_IBMSG3_off            (NTB_HW_REG_off + 0xA0)
#define NTB_REG_IBMSG3_STS_MSK_SP_off (NTB_HW_REG_off + 0xA4)
#define NTB_REG_IBMSG3_STS_off        (NTB_HW_REG_off + 0xA4)
#define NTB_REG_IBMSG3_MSK_off        (NTB_HW_REG_off + 0xA5)
#define NTB_REG_IBMSG3_SP_off         (NTB_HW_REG_off + 0xA6)

#define NTB_REG_IBMSG_MSK_val     0x00
#define NTB_REG_IBMSG_UNMSK_val   0x01
#define NTB_REG_IBMSG_STS_mask    0x01
#define NTB_REG_IBMSG_SP_mask     0x003F
#define NTB_REG_QUAD_UNMSK_val    0xFFFFFFFFFFFFFFFF
#define NTB_REG_DWORD_UNMSK_val   0xFFFFFFFF


/*MACRO DEFINITION*/
#define SG_OUTPUT_DATALEN 		8192
#define SG_RAW_DATALEN			1016
#define DESC_FMT_SENSE_DATA_SIZE 8

/*
 *  SENSE KEYS
 */

#define NO_SENSE            0x00
#define RECOVERED_ERROR     0x01
#define NOT_READY           0x02
#define MEDIUM_ERROR        0x03
#define HARDWARE_ERROR      0x04
#define ILLEGAL_REQUEST     0x05
#define UNIT_ATTENTION      0x06
#define DATA_PROTECT        0x07
#define BLANK_CHECK         0x08
#define COPY_ABORTED        0x0a
#define ABORTED_COMMAND     0x0b
#define VOLUME_OVERFLOW     0x0d
#define MISCOMPARE          0x0e

/* SCSI ADDITIONAL SENSE Codes */

#define SCSI_ASC_NO_SENSE				0x00
#define SCSI_ASC_PERIPHERAL_DEV_WRITE_FAULT		0x03
#define SCSI_ASC_LUN_NOT_READY				0x04
#define SCSI_ASC_WARNING				0x0B
#define SCSI_ASC_LOG_BLOCK_GUARD_CHECK_FAILED		0x10
#define SCSI_ASC_LOG_BLOCK_APPTAG_CHECK_FAILED		0x10
#define SCSI_ASC_LOG_BLOCK_REFTAG_CHECK_FAILED		0x10
#define SCSI_ASC_UNRECOVERED_READ_ERROR			0x11
#define SCSI_ASC_MISCOMPARE_DURING_VERIFY		0x1D
#define SCSI_ASC_ACCESS_DENIED_INVALID_LUN_ID		0x20
#define SCSI_ASC_ILLEGAL_COMMAND			0x20
#define SCSI_ASC_ILLEGAL_BLOCK				0x21
#define SCSI_ASC_INVALID_CDB				0x24
#define SCSI_ASC_INVALID_LUN				0x25
#define SCSI_ASC_INVALID_PARAMETER			0x26
#define SCSI_ASC_FORMAT_COMMAND_FAILED			0x31
#define SCSI_ASC_INTERNAL_TARGET_FAILURE		0x44

/* SCSI ADDITIONAL SENSE Code Qualifiers */

#define SCSI_ASCQ_CAUSE_NOT_REPORTABLE			0x00
#define SCSI_ASCQ_FORMAT_COMMAND_FAILED			0x01
#define SCSI_ASCQ_LOG_BLOCK_GUARD_CHECK_FAILED		0x01
#define SCSI_ASCQ_LOG_BLOCK_APPTAG_CHECK_FAILED		0x02
#define SCSI_ASCQ_LOG_BLOCK_REFTAG_CHECK_FAILED		0x03
#define SCSI_ASCQ_FORMAT_IN_PROGRESS			0x04
#define SCSI_ASCQ_POWER_LOSS_EXPECTED			0x08
#define SCSI_ASCQ_INVALID_LUN_ID			0x09


/*
 *  SCSI Architecture Model (SAM) Status codes. Taken from SAM-3 draft
 *  T10/1561-D Revision 4 Draft dated 7th November 2002.
 */
#define SAM_STAT_GOOD            0x00
#define SAM_STAT_CHECK_CONDITION 0x02
#define SAM_STAT_CONDITION_MET   0x04
#define SAM_STAT_BUSY            0x08
#define SAM_STAT_INTERMEDIATE    0x10
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14
#define SAM_STAT_RESERVATION_CONFLICT 0x18
#define SAM_STAT_COMMAND_TERMINATED 0x22	/* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL   0x28
#define SAM_STAT_ACA_ACTIVE      0x30
#define SAM_STAT_TASK_ABORTED    0x40

/*
 *  Status codes. These are deprecated as they are shifted 1 bit right
 *  from those found in the SCSI standards. This causes confusion for
 *  applications that are ported to several OSes. Prefer SAM Status codes
 *  above.
 */

#define GOOD                 0x00
#define CHECK_CONDITION      0x01
#define CONDITION_GOOD       0x02
#define BUSY                 0x04
#define INTERMEDIATE_GOOD    0x08
#define INTERMEDIATE_C_GOOD  0x0a
#define RESERVATION_CONFLICT 0x0c
#define COMMAND_TERMINATED   0x11
#define QUEUE_FULL           0x14
#define ACA_ACTIVE           0x18
#define TASK_ABORTED         0x20

#define STATUS_MASK          0xfe

/*
 * Host byte codes
 */

#define DID_OK          0x00	/* NO error                                */
#define DID_NO_CONNECT  0x01	/* Couldn't connect before timeout period  */
#define DID_BUS_BUSY    0x02	/* BUS stayed busy through time out period */
#define DID_TIME_OUT    0x03	/* TIMED OUT for other reason              */
#define DID_BAD_TARGET  0x04	/* BAD target.                             */
#define DID_ABORT       0x05	/* Told to abort for some other reason     */
#define DID_PARITY      0x06	/* Parity error                            */
#define DID_ERROR       0x07	/* Internal error                          */
#define DID_RESET       0x08	/* Reset by somebody.                      */
#define DID_BAD_INTR    0x09	/* Got an interrupt we weren't expecting.  */
#define DID_PASSTHROUGH 0x0a	/* Force command past mid-layer            */
#define DID_SOFT_ERROR  0x0b	/* The low level driver just wish a retry  */
#define DID_IMM_RETRY   0x0c	/* Retry without decrementing retry count  */
#define DID_REQUEUE	0x0d	/* Requeue command (no immediate retry) also
				 * without decrementing the retry count	   */
#define DID_TRANSPORT_DISRUPTED 0x0e /* Transport error disrupted execution
				      * and the driver blocked the port to
				      * recover the link. Transport class will
				      * retry or fail IO */
#define DID_TRANSPORT_FAILFAST	0x0f /* Transport class fastfailed the io */
#define DID_TARGET_FAILURE 0x10 /* Permanent target failure, do not retry on
				 * other paths */
#define DID_NEXUS_FAILURE 0x11  /* Permanent nexus failure, retry on other
				 * paths might yield different results */
#define DID_ALLOC_FAILURE 0x12  /* Space allocation on the device failed */
#define DID_MEDIUM_ERROR  0x13  /* Medium error */
#define DRIVER_OK       0x00	/* Driver status                           */

/* Misc. defines */
#define FIXED_SENSE_DATA				0x70
#define DESC_FORMAT_SENSE_DATA				0x72
#define FIXED_SENSE_DATA_ADD_LENGTH			10
#define LUN_ENTRY_SIZE					8
#define LUN_DATA_HEADER_SIZE				8
#define ALL_LUNS_RETURNED				0x02
#define ALL_WELL_KNOWN_LUNS_RETURNED			0x01
#define RESTRICTED_LUNS_RETURNED			0x00
#define NVME_POWER_STATE_START_VALID			0x00
#define NVME_POWER_STATE_ACTIVE				0x01
#define NVME_POWER_STATE_IDLE				0x02
#define NVME_POWER_STATE_STANDBY			0x03
#define NVME_POWER_STATE_LU_CONTROL			0x07
#define POWER_STATE_0					0
#define POWER_STATE_1					1
#define POWER_STATE_2					2
#define POWER_STATE_3					3
#define DOWNLOAD_SAVE_ACTIVATE				0x05
#define DOWNLOAD_SAVE_DEFER_ACTIVATE			0x0E
#define ACTIVATE_DEFERRED_MICROCODE			0x0F
#define FORMAT_UNIT_IMMED_MASK				0x2
#define FORMAT_UNIT_IMMED_OFFSET			1
#define KELVIN_TEMP_FACTOR				273
#define FIXED_FMT_SENSE_DATA_SIZE			18
#define DESC_FMT_SENSE_DATA_SIZE			8

#define SWITCHTEC_IOCTL_SG_CMD 8837
#define SG_OEM_PAGE					127

typedef enum SG_OPCODE{
	SG_RECV_OPCODE = 0,
	SG_SEND_OPCODE,
	SG_TURS_OPCODE,
	SG_INQUIRY_OPCODE
}SG_OPCODE;



/*****************************************************************************
 *				MAPPING TABLE MACROS
 ****************************************************************************/

/*****************************************************************************
 *				IOCTL IDENTIFIER MACROS
 ****************************************************************************/

/*****************************************************************************
 *				ENUMERATION CONSTANTS
 ****************************************************************************/
enum mrpc_sg_state {
	MRPC_SG_IDLE = 0,
	MRPC_SG_QUEUED,
	MRPC_SG_RUNNING,
	MRPC_SG_DONE,
};


/* Direction of DMA operation */

typedef enum DMA_DIR {

    DMA_DIR_L2L,      /* Local memory to local memory DMA operation */
    DMA_DIR_L2P,      /* Local memory to PCI memory DMA operation */
    DMA_DIR_P2L,      /* PCI memory to local memory DMA operation */
    DMA_DIR_P2P,      /* PCI memory to PCI memory DMA operation */

} DMA_DIR;


/*
 * Ioctl identifiers
 */
typedef enum IOCTL_ID {

    IOCTL_SW_FAILOVER = 1,
    IOCTL_SIG_FAILOVER,
    IOCTL_WDOG_FAILOVER,
    PSXAPP_OPCODE_GET_CONTROLLER_INFO = 9,
    PSXAPP_OPCODE_TWI_ACCESS,
    PSXAPP_OPCODE_VGPIO_ACCESS,
    PSXAPP_OPCODE_FAN_ACCESS,
    PSXAPP_OPCODE_DIE_TEMP,
    PSXAPP_OPCODE_FWFLASH,
    PSXAPP_OPCODE_GET_FWLOG,
    PSXAPP_OPCODE_PMON,
    PSXAPP_OPCODE_PORTLANE,
    PSXAPP_OPCODE_PORT_ARBITRATION,
    PSXAPP_OPCODE_MCOVERLAY,
    PSXAPP_OPCODE_STACKBIFURCATION,
    PSXAPP_OPCODE_PORTPARTP2PBIND,
    PSXAPP_OPCODE_DIAG_TLPINJECT,
    PSXAPP_OPCODE_DIAG_TLPGENCHK,
    PSXAPP_OPCODE_DIAG_PORTEYECAPTURE,
    PSXAPP_OPCODE_DIAG_PORTVHIST,
    PSXAPP_OPCODE_DIAG_PORTLTSSMLOG,
    PSXAPP_OPCODE_DIAG_PORTTLPANALYZER,
    PSXAPP_OPCODE_PORTLANEADAPTOBJECTS,
    PSXAPP_OPCODE_READRXDIAG,
    PSXAPP_OPCODE_WRITETXDIAG,
    PSXAPP_OPCODE_READVPD,
    PSXAPP_OPCODE_PMCPSX
} IOCTL_ID;

/* 
 * Argument structure to IOCTL function 
 */

struct ntb_stub_args {
    unsigned char system_id;
    unsigned long size;
};


typedef enum LOCATION {

    LOCAL,
    REMOTE

} LOCATION;

/*
 * Buffer pool sizes in the aperture
 */
typedef enum BUF_POOL {

    HUGE_POOL,
    LARGE_POOL,
    BIG_POOL,
    MEDIUM_POOL,
    SMALL_POOL,
    TINY_POOL

} BUF_POOL;

/* 
 * Used for representing the type of deployment the driver is running 
 */

typedef enum DEPLOYMENT_TYPE {

    SINGLE_SWITCH = 1,
    PUNCH_THROUGH,
    SYS_INTERCONNECT_RP,
    SYS_INTERCONNECT_EP,

} DEPLOYMENT_TYPE;

/*
 * Global states to detect the initialization of the NTB driver
 */
typedef enum GLOBAL_STATE {

    GLOBAL_STATE_START = 1,
    GLOBAL_STATE_INIT_DONE,

} GLOBAL_STATE;

typedef enum ACCESS_TYPE {

    CONFIG_ACCESS = 1,
    MEMORY_ACCESS,

} ACCESS_TYPE;

typedef enum BAR_MODE {
	DIRECT_WINDOW = 1,
	LUT_WINDOW,
	COMB_WINDOW,
} BAR_MODE; 

typedef enum BAR_ADDRESS {
	BAR_32BIT = 0,
    BAR_64BIT,
} BAR_ADDRESS;
	
/* 
 * Used for representing PCI BAR register indexes 
 */

typedef enum PCI_BAR {

    PCI_BAR_0,    /* BAR0 Identifier */
    PCI_BAR_1,    /* BAR1 Identifier */
    PCI_BAR_2,    /* BAR2 Identifier */
    PCI_BAR_3,    /* BAR3 Identifier */
    PCI_BAR_4,    /* BAR4 Identifier */
    PCI_BAR_5,    /* BAR5 Identifier */

} PCI_BAR;

/* 
 * Used for representing function service drivers and base layer driver
 */

typedef enum DSID {

    DSID_BASE,   /* Identifier for base layer of the driver */
    DSID_NET,    /* Identifier for the net function service */
    DSID_RAW,    /* Identifier for the raw data function service */

    /* Any new function identifier has to be added here */
    DSID_MAX,

} DSID;

/* 
 * Used for representing the events between the peer function service drivers
 */

typedef enum FUNC_EVENT {

    EVENT_INIT,         /* Function serivce init event. At the time of reset of 
                                                IPC state machine, this event is sent by base layer */
                                               
    EVENT_LOCAL_READY,  /* Function service map event. Function service specific 
			                           structure is setup in the aperture when this is seen */
			                           
    EVENT_REMOTE_READY, /* Function service ready event. This event is received 
			                           after base layer's IPC gets completed */
} FUNC_EVENT;

typedef enum ERROR_CODE {
    
    DRIVER_INIT_INCOMPLETE = 0x200,
    DRIVER_FAILOVER_FAILED

} ERROR_CODE;

#define INTEL_ROOT_PORT_MPS 0x01

/*
 * Maximum Read Request Sizes
 */
typedef enum MRRS_FIELD {
    NTB_MRRS_128BYTES,
    NTB_MRRS_256BYTES,
    NTB_MRRS_512BYTES,
    NTB_MRRS_1024BYTES,
    NTB_MRRS_2048BYTES,
    NTB_MRRS_4096BYTES
} MRRS_FIELD;

typedef enum mrpc_cmds_e{
    /** 1 ~ 62 reserved for PMC */
    /** 0  */
    MRPC_DIAG_PMC_START,
    /** 1  */
    MRPC_TWI,
    /** 2  */
    MRPC_VGPIO,
    /** 3  */
    MRPC_PWM,
    /** 4  */
    MRPC_DIETEMP,
    /** 5  */
    MRPC_FWDNLD,
    /** 6  */
    MRPC_FWLOGRD,
    /** 7  */
    MRPC_PMON,
    /** 8 */
    MRPC_PORTLN,
    /** 9 */
    MRPC_PORTARB,
    /** 10 */
    MRPC_MCOVRLY,
    /** 11 */
    MRPC_STACKBIF,
    /** 12 */
    MRPC_PORTPARTP2P,
    /** 13 */
    MRPC_DIAG_TLP_INJECT,
    /** 14 */
    MRPC_DIAG_TLP_GEN,
    /** 15 */
    MRPC_DIAG_PORT_EYE,
    /** 16 */
    MRPC_DIAG_POT_VHIST,
    /** 17 */
    MRPC_DIAG_PORT_LTSSM_LOG,
    /** 18 */
    MRPC_DIAG_PORT_TLP_ANL,
    /** 19 */
    MRPC_DIAG_PORT_LN_ADPT,

    /** 65 ~ 126 reserved for user */
    /** 65  */
    MRPC_ECHO = 65,
    
    /*70*/
    MRPC_SES_PAGE = 70,
    
    /** MRPC_DIAG_USER_END should be less than MRPC_CMDS_MAX */
    MRPC_DIAG_USER_END,

} mrpc_cmds_enum;

/* fw download sub command type */
typedef enum
{
    FWDNLD_SUB_CMD_GET_STATUS = 0, // get status
    FWDNLD_SUB_CMD_FW_UPGRADE,     // upgrade fw
    FWDNLD_SUB_CMD_NO_EXIST,
} fwdnld_sub_cmds_enum;

/* P2P  sub command type */
typedef enum
{
    P2P_BIND_SUB_CMD_BIND               = 0, // BIND PORT
    P2P_BIND_SUB_CMD_UNBIND,                 // UNBIND PORT
    P2P_BIND_SUB_CMD_PORT_BIND_INFO,         // PORT BIND INFO
    P2P_BIND_SUB_CMD_PART_BIND_INFO,         // PART BIND INFO
    P2P_BIND_SUB_CMD_NO_EXIST,
}p2p_bind_sub_cmds_enum;

/* gpio sub command type */
typedef enum
{
    GPIO_SUB_CMD_GET_DIR_CFG           = 0,
    GPIO_SUB_CMD_GET_POL_CFG,
    GPIO_SUB_CMD_GET_PIN_VAL,
    GPIO_SUB_CMD_SET_PIN_VAL,
    GPIO_SUB_CMD_ENA_PIN_INT,
    GPIO_SUB_CMD_DIS_PIN_INT,
    GPIO_SUB_CMD_CLR_PIN_INT,
    GPIO_SUB_CMD_GET_ALL_PINS_STAT,
    GPIO_SUB_CMD_NO_EXIST,
}gpio_sub_cmds_enum;

/* ioctl cmd_type */
typedef enum
{
  MRPC_CMD,
  SG_SPEC_PAGE=127, //for sg specific page decode in mrpc
  SW_EVENT_GET= 128, // Non-MRPC cmds should use different numbers because 0-126 are reserved
  CSR_REG_READ,      // for MRPC related commands. On the application side it matters because
  CSR_REG_WRITE,     // it does not differentiate between MRPC and non-MRPC cmds until the
  BAR_REG_READ,      // ioctl is sent.
  BAR_REG_WRITE
} CMD_TYPE;

typedef enum OP_MODE {
	OP_MODE_P2P      = 0x0,
    OP_MODE_P2P_NTB  = 0x1,
    OP_MODE_P2P_MGMT = 0x2,
    OP_MODE_NTB      = 0x3,
    OP_MODE_USP_VRC  = 0x4,
} OP_MODE;

/* This data structure is used to store the information related to a data 
 * frame that is sent from one EP to other */

typedef struct __pmc_ntb_frame {

    struct list_head        list;       /* Used to queue frames */
    u32                     DSID;       /* Device Service ID */
    atomic_t                ref_count;  /* Reference count which indicates number of users of this frame */
    void                    *aperture;  /* Aperture pointer to access the queue in case of Ethernet and Raw data service layer */
    u32                     status;     /* The status to be passed to the destructor function */
    u32                     frags;      /* Indicate number of fragments */
    u32                     flags;      /* Indicates special handling of frame*/
    void                    *func_priv; /* To store function service layer data, such as skb */
    void                    *func_data; /* To store function service layer data, such as ndev */
    void                    *func;      /* Function service structure */
    void                    *local_ep;  /* Stores pmc_ntb_local_ep structure instance */
    void                    *remote_ep; /* Stores pmc_ntb_remote_ep structure instance */
    void                    *local;     /* Stores pmc_ntb_mem_local structure */
    struct __pmc_ntb_frame *source_frame; /* Source frame from which this frame is cloned */                                        
    void (*frame_ds_cb)(struct __pmc_ntb_frame *frame); /* Destructor callback function that is called to deallocate a frame */
                                        
    /* Followed by data fragments */
    /* In case of received frame, pmc_ntb_rx is followed */
} pmc_ntb_frame;

struct switchtec_user_sg {
	struct switchtec_dev *stdev;

	enum mrpc_sg_state state;

	struct completion comp;
	struct kref kref;
	struct list_head list;

	u32 cmd;
	u32 status;
	u32 return_code;
	size_t data_len;
	size_t read_len;
	unsigned char data[SWITCHTEC_MRPC_PAYLOAD_SIZE];
	int event_cnt;
};



/*****************************************************************************
 *				CALLBACK FUNCTIONS
 ****************************************************************************/

/* DMA callback function */
typedef void (*pmc_ntb_dma_cb)(int status, void* cb_data);


/* Data frame destructor callback function */
typedef void (*pmc_ntb_frame_ds_cb)(pmc_ntb_frame *frame);

/* Callback to send the received frame to function service driver */
typedef int (*pmc_ntb_frame_receive_cb)(void *local_ep, void *remote_ep, void *func);

/* Callback to send the received frame to application */
typedef int (*pmc_ntb_func_rx_cb)(pmc_ntb_frame *frame);


/*****************************************************************************
 *				DATA STRUCTURES
 ****************************************************************************/
/* DMA fragment structure that is filled at the end of pmc_ntb_tx structure  
 * during frame transfer */

typedef struct __pmc_ntb_dma_frag {

	unsigned long dst;	  /* Destination address of the DMA operation */
	unsigned long src;	  /* Source address of the DMA operation */
	u32 		  len;	  /* Length of the DMA fragment */

} pmc_ntb_dma_frag;


/* DMA data that is passed along as argument for DMA callback function. 
 * Function service layer fills the callback function in dma_cb 
 * argument */

typedef struct __pmc_ntb_dma {

	struct list_head	list;	  /* For queuing the DMA trasfer requests */
	DMA_DIR 			dma_direction;
								  /* Direction of DMA transfer */
	u32 				frags;	  /* Number of DMA fragments */
	pmc_ntb_dma_cb	 dma_cb;   /* DMA callback function */
	void				*cb_data; /* DMA callback data */
	u32 				status;   /* status of the DMA operation */
	u32 				align;

} pmc_ntb_dma;


typedef struct ioctl64_s
{
    u32 signature;
    u16 majorFunction;
    u16 minorFunction;
    u32 length;
    u32 status;
    u32 functionSpecificArea[12];
}ioctl64_t;

typedef s32 pmc_ntb_dma_cookie;

/* Base layer part of the aperture data structure. It contains the registers 
 * used for event base communication between the NT end points. Some part of 
 * this structure is reserved for future usage. Totally 64KB is reserved for 
 * base layer data */

typedef struct __base_data {

    u64    remote_event_count_valid;      /* Used by remote EP to send an event to local EP */
    u64    local_event_count_valid;       /* Used by local EP to maintain processed event count */
    u64    remote_event_count_done;
    u64    local_event_count_done;
    u64    remote_event_count_pkt;
    u64    local_event_count_pkt;
    u8     wrap_around_flag;
    u32    reserved[APERTURE_PRIV_MAX];   /* Reserved space for future use */

} base_data;

typedef struct
{
  u32 signature;
  u32 cmd_type;
  u32 command;
  u32 subcommand;
  u32 *mrpcStatus;
  u32 *mrpcRetVal;
  u32 input_length;
  u32 output_length;
  u32 *inputData;
  u32 *outputData;
  u32  dev_index;
  char *dev_name;
} IOCTL;

typedef struct
{
  u32 signature;
  u32 cmd_type;
  u32 offset;
  u32 size;
  u32 lowdw;
  u32 highdw;
  u32 dev_index;
}REG_RD_IO;

typedef struct
{
  u32 signature;
  u32 cmd_type;
  u32 offset;
  u32 size;
  u32 dev_index;
  u64 data;
}REG_WR_IO;

typedef struct _gbl_event_header
{  
  u32 gb_hd_stk;
  u32 gb_hd_ppu;
  u32 gb_hd_isp;
  u32 gb_hd_reset;
  u32 gb_hd_except;
  u32 gb_hd_nmi;
  u32 gb_hd_non_fatal;
  u32 gb_hd_fatal;
  u32 gb_hd_twi_mrpc_cmp;
  u32 gb_hd_twi_mrpc_async_cmp;
  u32 gb_hd_cli_mrpc_cmp;
  u32 gb_hd_cli_mrpc_async_cmp;
} gbl_event_header;

typedef struct _gbl_event_data
{  
  u32 gb_da_stk;
  u32 gb_da_ppu;
  u32 gb_da_isp;
  u32 gb_da_sys_rst;  //u8
  u32 gb_da_except;
  u32 gb_da_nmi;
  u32 gb_da_non_fatal;
  u32 gb_da_fatal;
  u32 gb_da_twi_mrpc_cmp;       //u16
  u32 gb_da_twi_mrpc_async_cmp; //u16
  u32 gb_da_cli_mrpc_cmp;       //u16
  u32 gb_da_cli_mrpc_async_cmp; //u16
} gbl_event_data;

typedef struct _part_event_header
{  
  u32 part_hd_reset;
  u32 part_hd_mrpc_cmp;
  u32 part_hd_mrpc_async_cmp;
} part_event_header;

typedef struct _part_event_data
{  
  u32 part_da_rst;            //u8
  u32 part_da_mrpc_cmp;       //u16
  u32 part_da_mrpc_async_cmp; //u16
} part_event_data;

typedef struct _port_event_header
{  
  u32 port_hd_aer_p2p;
  u32 port_hd_aer_vep;
  u32 port_hd_dpc;
  u32 port_hd_cts;
  u32 port_hd_uec;
  u32 port_hd_hp;
  u32 port_hd_int_err;
  u32 port_hd_thrhld;
  u32 port_hd_pwr;
  u32 port_hd_tlp_thrtg;
  u32 port_hd_for_spd;
  u32 port_hd_cdt_tmo;
} port_event_header;

#define AER_EVT_DATA_MAX 5
#define CTS_EVT_DATA_MAX 2
#define UEC_EVT_DATA_MAX 4

typedef struct _port_event_data
{  
  u32 port_da_aer_p2p[AER_EVT_DATA_MAX];
  u32 port_da_aer_vep[AER_EVT_DATA_MAX];
  u32 port_da_dpc;       //u8
  u32 port_da_cts[CTS_EVT_DATA_MAX];
  u32 port_da_uec[UEC_EVT_DATA_MAX];
  u32 port_da_hp;        //u8
  u32 port_da_int_err;
  u32 port_da_thrhld;
  u32 port_da_pwr;       //u8
  u32 port_da_tlp_thrtg; //u8
  u32 port_da_for_spd;   //u16
  u32 port_da_cdt_tmo;
} port_event_data;

typedef struct _port_event
{ 
  u32 inst_id;
  u32 part_id;
  u32 evt_port_sum;
  port_event_header evt_port_hd;
  port_event_data evt_port_data;
} port_event;

typedef struct _part_event
{ 
  u64 evt_lgl_port_bitmap;
  u32 part_id;
  u32 evt_msi_vtr_rpt;
  u32 evt_part_sum;
  part_event_header evt_part_hd;
  part_event_data evt_part_data;
} part_event;

typedef struct _psx_sw_event
{  
  u64 evt_ctl;
  u64 evt_part_bitmap;
  u32 evt_happen;     /* true or false if event happened in switch */
  u32 evt_gbl_sum;
  u32 evt_part_cnt;   /* how many parittions in which event happened */
  u32 evt_port_cnt;
  gbl_event_header evt_gbl_hd;
  gbl_event_data evt_gbl_data;
  part_event evt_part[SWITCH_PORT_MAX];
  port_event evt_port[SWITCH_PORT_MAX];
} psx_sw_event;


typedef struct
{
  u32 signature;
  u32 cmd_type;
  psx_sw_event event;
  u32 dev_index;
} sw_event_ioctl;


/*****************************************************************************
 *				FUNCTION DECLARATIONS
 ****************************************************************************/

/* Function pointer for data transfer APIs using DMA channel or memory copy */

typedef int (*pmc_ntb_dma_start_cb)(DMA_DIR direction, 
							   u32 frags,
					   pmc_ntb_dma_frag *dma_frags,
					   pmc_ntb_dma_cb cb,
					   void *cb_data,
					   unsigned long virt_base,
					   unsigned long phys_base);


/* Function to do the data transfer using memory copy */
int pmc_dma_start_memcpy(DMA_DIR direction, 
					u32 frags, 
					pmc_ntb_dma_frag *dma_frags,
					pmc_ntb_dma_cb cb,
					void *cb_data, 
					unsigned long virt_base,
					unsigned long phys_base);


unsigned long 
virt_pciio_to_phys(unsigned long virt_base, 
		   unsigned long phys_base, 
		   unsigned long addr);

int pmc_psx_open(struct inode *, 	struct file *);
int pmc_psx_close(struct inode *, struct file *);
long pmc_psx_ioctl(struct file *, unsigned int, unsigned long);
long pmc_psx_compat_ioctl(struct file *, unsigned int, unsigned long);
int pmc_psx_mmap(struct file *file, struct vm_area_struct *vma);
int pmc_psx_spec_page_decode(struct file *filp,IOCTL* io);

int fem_sg_open(struct inode *inode, struct file *filp);
int fem_sg_close(struct inode *inode, struct file *filp);

inline int cls_scsi_status_is_good(int status);
int fem_sg_completion(sg_io_hdr_t *hdr, u8 status, u8 sense_key,u8 asc, u8 ascq);
void fem_sg_sense_check(sg_io_hdr_t *io,int sg_ret,u8* tmp_buf,int len);

int cls_fem_open(struct inode *inode, struct file *filp);
int cls_fem_close(struct inode *inode, struct file *filp);

long cls_fem_ioctl(struct file *filp,
                   unsigned int cmd_in,
                   unsigned long arg);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,6))
long fem_sg_ioctl(struct file *filp,unsigned int cmd_in,unsigned long arg);
#else
int fem_sg_ioctl(struct inode *inode,struct file *filp,unsigned int cmd_in,unsigned long arg);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,6))
long pmc_psx_ioctl(struct file *, unsigned int, unsigned long);
#else
int pmc_psx_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
#endif


void stuser_set_state_sg(struct switchtec_user_sg *stuser,enum mrpc_sg_state state);
void stuser_free_sg(struct kref *kref);
void stuser_put_sg(struct switchtec_user_sg *stuser);
void mrpc_cmd_submit_sg(struct switchtec_dev *stdev);
void mrpc_complete_cmd_sg(struct switchtec_dev *stdev);
void mrpc_cmd_submit_sg(struct switchtec_dev *stdev);
int mrpc_queue_cmd_sg(struct switchtec_user_sg *stuser);
int lock_mutex_and_test_alive_sg(struct switchtec_dev *stdev);


/* Statistics of frames */
typedef struct __pmc_ntb_stats {
    u64 tx_frames;         /* Frames transmitted */
    u64 tx_bytes;          /* Bytes transmitted  */
    u64 tx_errors;         /* Transmit errors    */
    u64 rx_frames;         /* Frames received    */
    u64 rx_bytes;          /* Bytes received     */
    u64 rx_errors;         /* Receive errors     */
} pmc_ntb_stats;

/* Tx callback data */
typedef struct __pmc_ntb_tx {

    u32               hdr_len;
    u32               bufs;
    u32               frags;
    pmc_ntb_frame  *frame;
    void              *local_ep;
    void              *remote_ep;
    unsigned long     *entry;
    /* Followed by:
       Array of unsigned long entries
       Array of pmc_ntb_x_hdr 
       Array of pmc_ntb_dma_frag */

} pmc_ntb_tx;

/* Rx callback data */

typedef struct __pmc_ntb_rx {

    unsigned long        entry;
    u32                  frags;
    pmc_ntb_dma_frag  *frag;

} pmc_ntb_rx;

/* Tx/Rx header format that is placed after pmc_ntb_frame structure. From 
 * this, the data length of the following DMA fragment will be taken. */

typedef struct __pmc_ntb_x_hdr {

    u32   hdr_len;           /* Length of the header */
    u32   data_len;          /* Length of the data */

} pmc_ntb_x_hdr;     

/* This represents a buffer fragment. For Ethernet and Raw data function 
 * service, it stores skb and its length */

typedef struct __pmc_ntb_frag {

    u8   *buf;           /* Pointer to the data fragment */
    u32   len;           /* Length of the data fragment */

} pmc_ntb_frag;     


/* This data structure is used to store the addresses of the buffers allocated 
 * remotely(at remote EP) for a function service */

typedef struct __pmc_ntb_mem_remote {

    u64               func_trans_base; /* Physical address of the remote function layer buffer */                                
    u64               actual_func_trans_base;
    unsigned long     size;      /* Size of the buffer in bytes */
    unsigned long     physical;  /* Physical address of the memory mapped I/O buffer */
    void              *buffer;   /* Starting address of the memory mapped I/O */
    void              *remote_func_data; /* Function layer data structure that is filled by the function layer */                                 
    u32               inited;    /* Flag indicating the initialization of remote memory for remote EP */
} pmc_ntb_mem_remote;

/* This data structure is used to store the addresses of the buffers allocated 
 * locally for a function service */

typedef struct __pmc_ntb_mem_local {
    
    unsigned long     size;      /* Size of the buffer in bytes */
    unsigned long     physical;  /* Physical address of the aligned buffer */
    void              *base;     /* Pointer to actual buffer allocated */
    void              *buffer;   /* Pointer to the buffer after alignment */
    void              *local_func_data; /* Function layer data structure that is filled by the function layer */
    u32               inited;    /* Flag indicating the initialization of local memory for remote EP */
} pmc_ntb_mem_local;

/* This data structure is used to store the inbound and outbound IPC 
 * messages. An IPC queue is maintained for both inbound and outbound IPC 
 * traffic */

typedef struct __pmc_ntb_ipc {

    struct list_head   list;          /* List to queue IPC messages */ 
    u32                msg[MSG_MAX];  /* Actual storage of IPC messages */

} pmc_ntb_ipc;

typedef struct __ntb_barsetup_info {
	u8               valid;           /* bar is valid or invalid */
	u8               mode;            /* bar window mode, direct window(1), NT window(2), or combination(3) */
	u8               type;            /* 32-bit or 64-bit */
	u8               prefetch;
	u8               dir_win_used;	
}ntb_barsetup_info;

/* This data structure is used to store information related to a BAR 
 * that is enumerated by the kernel/BIOS and is probed by the driver */

typedef struct __pmc_ntb_bar_info {

    unsigned long    bar_hw_addr;     /* Physical address of the memory mapped using this BAR */
    void __iomem     *bar_va_addr;    /* Virtual address of the memory mapped using this BAR */
    unsigned long    resource_len;    /* Size of the memory mapped using this BAR */
	ntb_barsetup_info barsetup;
} pmc_ntb_bar_info;


typedef struct __pmc_ntb_buf_pool {

    spinlock_t    buf_lock;            /* Lock for the buffer pool */
    unsigned long size;               /* Size of the buffer pool */
    unsigned long phys_addr[BUF_CHUNK_MAX]; /* Physical addresses of the buffers in the buffer pool */

    void          *virt_addr[BUF_CHUNK_MAX]; /* Virtual addresses of the buffers in the buffer pool */
    bool          used[BUF_CHUNK_MAX]; /* Flag to indicate if the buffer is used or not */
} pmc_ntb_buf_pool;


typedef struct __pmc_ntb_lut_status {
    bool    used;            /* Flag to indicate the LUT enty's status */
} pmc_ntb_lut_status;

typedef struct __ntb_lut {
	u32 xlate_addr_low;
	u32 xlate_addr_high;
    u8 target_part;
	u8 valid;
	u16 entry_index;
	u8 part_id;
}ntb_lut;

typedef struct __ntb_nt_window {
	u16 lut_base;
	u16 sub_win_num;
	u16 sub_win_xlate_pos;	
	u8 bar_no;
	u8 part_id;
}ntb_nt_window;

typedef struct __ntb_direct_window {
	u32 xlate_addr_low;
	u32 xlate_addr_high;
	u32 window_size;
	u8 xlate_pos;
	u8 target_part;
	u8 bar_no;
	u8 part_id;
}ntb_direct_window;

typedef struct __ntb_id_map_table {
	u16 bdf;
	u8  xlate_tag;       /* proxy DF */
	u8  valid;
	u16 entry_index;
	u8 RNS;
	u8 CNS;
    u8 ATP;
	u8 part_id;
}ntb_id_map_table;


/* This data structure is used to store the common fields of the local and 
 * remote EP structures */

typedef struct __common_ep_fields {

    /* Variables for an endpoint identification */
    u8   port;        /* Port number of the endpoint */
    u8   partition;   /* Partition ID of the endpoint */
    u8   op_mode;     /* Operation mode of the endpoint */
	u8   inst_id;     /* instance ID of port */
    u8   system_id;   /* Unique identifier of the endpoint */
} common_ep_fields;

/* This data structure is allocated when PMC's NT endpoint(which is a PCIe 
 * device) is detected in the driver. The NT endpoint is detected by the kernel 
 * and driver's probe function is called for every detected endpoint device. 
 * The probe function will allocate this structure for every endpoint and is 
 * maintained as a linked list.
 *
 * For "Single NTB" & "Punch-through" cases the list will have only one node. 
 * For "System interconnect" case, the list is populated with all the EPs 
 * detected in the driver's probe function */

typedef struct __pmc_ntb_local_ep {

    struct list_head    list;             /* Used for linking all the detected  local endpoints */
    struct list_head    remote_ep_list;   /* Head pointer for the remote endpoint list. The members are of 
					                                             type pmc_ntb_remote_ep */
    char                name[DEV_NAME_MAX]; /* Name of the local NTB endpoint */                                          
    struct pci_dev      *pdev;              /* Saved pointer to pci_dev struct */
    pmc_ntb_bar_info pci_bar[PCI_NUM_BARS]; /* Enumerated BAR addresses for local EP */
    unsigned long       allocated_resource; /* Length of the BAR4 resource that is occupied by the EPs */
    unsigned long       base_data_offset;
	bool                lut_mask[AT_ENTRY_MAX];
	pmc_ntb_lut_status 	local_bar_LUT[AT_ENTRY_MAX]; /* Address translation values for BAR */	

    u64                 mtbl_index_bitmap;
    bool                mtbl_sysint_done;
    bool                msi_enabled;      /* Flag indicating if MSI is enabled or not */
    bool                msix_enabled;      /* Flag indicating if MSI-X is enabled or not */
    struct msix_entry   msix_entries[MAX_MSIX_NUM_VECTOR];
	u8                  num_msix;
	u32                 msi_vector_num;   /* Event Report MSI Vector number */
	bool                nt_mode;          /* non-transparent mode */
    u8                  map_64_bit;       /* BARs used with 64 bit or 32 bit mapping */
	
    spinlock_t          msg_reg_lock;     /* Spinlock for register access */
    u64                 in_doorbell_status; /* Doorbell bits allocated for this remote EP. These bits 
					                                               need to be checked when an interrupt arrives */												   	
	u8	                p2p_cnt;	 /* p2p port count */
	u8	                part_cnt;	 /* partition count */

    common_ep_fields    local_ep_fields;  /* Common fields for both local and remote EPs. This instance is for local EP */
    u64                 lg_port_evt_bmp;  /* When a logical port in this partition has port event, the corresponding bit is set */
	 
	u16                 id_table_index;
	u16                 lut_index;
	u16                 nt_win_lut_index;
	u16                 bar2_sub_nt_win_cnt;
	u16                 bar4_sub_nt_win_cnt;
    u16                 barsetup_cnt;
	u16                 barsetup_off;
	u16                 id_table_entry_cnt;
	u16                 id_table_off;
	u16                 lut_entry_cnt;
	u16                 lut_off;
	
    u32                 map_config_ext_bitmap;
    u32                 map_ext_bitmap;
    u32                 map_ext_recv_bitmap;
    u32                 map_config_ext_recv_bitmap;

	struct semaphore 	mrpc_cmp_sem;
	struct semaphore 	mrpc_async_cmp_sem;
} pmc_ntb_local_ep;


/* This data structure is used to represent a remote EP. The fields in this 
 * structure facilitate the local EP to communicate with the remote EPs. */

typedef struct __pmc_ntb_remote_ep {
    
    struct list_head    list;         /* Used for linking all the detected remote endpoints */
    pmc_ntb_local_ep *parent_ep;      /* Parent endpoint for this remote endpoint. The parent will be local endpoint */
    void                *remote_rp;   /* Remote EP of the RP which is the interface for communicating with this endpoint */

    common_ep_fields    remote_ep_fields; /* Common fields for both local and remote EPs. This instance is for remote EP */
    pmc_ntb_stats    stats;               /* Data transfer statistics */
    u8                  deployment_type;  /* Tells if this port is a punch through port or not.
						                                     Since the scenarios can be mixed, the remote EP need to be flagged 
						                                     if it is punch through */
						                                     
    u8                  num_of_sys;     /* Number of systems inter-connected in system inter-conect topology */
    u32                 switch_num;     /* Identifier for the switch in which this remote EP is detected */
    u8                  config_or_memory;  /* Tells how the config_base pointer need to be used.
    					                                               It has to be used as normal memory access if BAR4 is assigned. 
    					                                               Otherwise it is equivalent to register access */

    /* Variables for IPC operations */
    u8                  ipc_tag;                /* Tag for matching requests with responses */
    atomic_t            ipc_state;              /* Current IPC state */
    atomic_t            ipc_free;               /* IPC regulating field */
    u32                 ipc_final_mapped_state; /* Final successful mapped IPC state */
    pmc_ntb_ipc       ipcs_in[IPC_MAX];       /* Array of IPC structures for incoming IPC messages */
    struct list_head    ipc_freelist_in;      /* IPC structures maintained as linked list to store incoming IPC messages */
    struct list_head    ipc_pendinglist_in;   /* IPC structures maintained as linked list to store incoming pending IPC messages */
    pmc_ntb_ipc       ipcs_out[IPC_MAX];      /* Array of IPC structures for outgoing IPC messages */
    struct list_head    ipc_freelist_out;     /* IPC structures maintained as linked list to store outgoing IPC messages */
    struct list_head    ipc_pendinglist_out;    /* IPC structures maintained as linked list to store outgoing pending IPC messages */
    spinlock_t          ipc_lock_in;            /* Spinlock for operations on ipc_freelist_in & ipc_pendinglist_in lists */
    spinlock_t          ipc_lock_out;           /* Spinlock for operations on ipc_freelist_out & ipc_pendinglist_out lists */
    struct timer_list   ipc_timer;              /* Timer for outgoing IPC message transmission */
    spinlock_t          local_event_lock;
    u8                  stop_ipc_timer;         /* Used to control IPC timer */
    u32                 remote_src_part;
    u32                 local_src_port;
    u32                 local_src_part;         /* Source partition on local switch which has sent IPC or to which messages have to 
						                                                be written. This is for a all ports behind PT port */   
    /* Variables for data transmission */
    pmc_ntb_tx       *tx;                    /* Saved transfer */
    struct tasklet_struct ntb_tasklet;       /* Tasklet for bottom half implementation of interrupt deferred procedure */
    base_data           *remote_base_data;      /* Pointer to the remote EP's base layer data */
    base_data           *local_base_data;       /* Pointer to the local EP's base layer data */
    void                *func_priv_data[DSID_MAX]; /* To store service layer data, such as queue, txq, 
    						                                                      and its related fields for Ethernet and Raw data services */
    pmc_ntb_mem_remote  mem_remote[DSID_MAX];   /* Remote memory region representation */
    pmc_ntb_mem_local   mem_local[DSID_MAX];    /* Local memory region representation */
    void                   *local_mem;          /* Local memory region starting address */
    void                   *remote_mem[PCI_NUM_BARS];  /* Remote memory region starting addresses in BAR2 & BAR4 regions */
    unsigned long          remote_mem_phys[PCI_NUM_BARS];
    u64                    ep_trans_base;       /* Physical address of the remote memory start address of EP */
    u64                    actual_ep_trans_base;
    u64                    mtbl_index_bitmap;
    pmc_ntb_buf_pool     local_buf_pool[BUF_POOL_MAX];  /* Buffer pool of local memory */

    pmc_ntb_buf_pool     remote_buf_pool[BUF_POOL_MAX]; /* Buffer pool of remote memory */
    u8                      index_in_bar[PCI_NUM_BARS]; /* Index of this remote EP in BAR regions. Only BAR2 & BAR4 are used*/
    u8                      initiate_func_hello;/* Flag to indicate that IPC hello messages can be initiated or not */	   
    u8                      last;
    u8                      last_config_ext;
    u8                      ok_map_config_ext_final;
    u8                      ok_map_ext_final;
    u8                      chanid;

} pmc_ntb_remote_ep;



/* This is the base data structure for the NTB driver. It is allocated as a 
 * global variable in the driver. Single instance of this structure is 
 * allocated in the driver. 
 *
 * It contains local endpoint linked list and data members allocated as a 
 * single instance across all EPs. Each node in local EP linked list is used 
 * to maintain information related to an EP that is locally detected in 
 * driver's probe function. */

typedef struct __pmc_ntb_global {

    struct list_head  local_ep_list;  /* Head pointer for the local endpoint list. The members are of type pmc_ntb_local_ep */
    DEPLOYMENT_TYPE   deployment_type;   /* Is this "Single NTB" or "Punch-through" or "System interconnect" scenario */
    GLOBAL_STATE      global_state;       /* Global state of the driver */
    u8                sys_inter_count;    /* Number of systems interconnected in system interconnect case */
    u8                num_of_systems;     /* Total number of remote EPs detected */
    u32               mapping_table[MT_ENTRY_MAX]; /* Mapping table values used by this end point */
    void              *func_data[DSID_MAX];  /* Function data like virtual ethernet, Raw data etc */
    u64               free_addr[DSID_MAX][NTB_MAX];  /* Maintains free addresses in the aperture. 
                                                                                                  * These are stored per function service. 
                                                                                                  * Maximum addresses per func service are 8. 
                                                                                                  * This is filled in pmc_ntb_func_register call */

    struct list_head  func_list;          /* Registered function services maintained as linked list */
    spinlock_t        func_list_lock;     /* Spinlock for the function service linked list */
    struct timer_list probe_timer;        /* Timer used to stop getting probe from kernel. 
                                                                              * On expiry, the IPC exchanges are started. 
                                                                              *  Main purpose of this is to get the number of 
					                                          * systems interconnected in system interconnect deployment */
					                                          
    u32               int_mask;           /* Interrupt mask */
    u64               dbell_mask;         /* Doorbell mask */
    u8                pt_switch_count;    /* Number of switches connected in PT way */

    /* DMA channel and data transfer related variables */
    pmc_ntb_dma_start_cb dma_start_cb; /* DMA start function pointer to select DMA transfer API based on registration */

    wait_queue_head_t failover_wait;      /* Wait queue used at the time of failover to wait till failover completes */
    u32               failover_init_done; /* Flag to mark the completion of failover initialization */
} pmc_ntb_global;

/*****************************************************************************
 *				CALLBACK FUNCTIONS
 ****************************************************************************/
/* Event callback for function layer driver synchronization with remote EPs */
typedef void (*pmc_ntb_ipc_event_cb)( void *local_ep, 
		                                  void *remote_ep, 
					                      void *func_data,
				                          DSID func_id,	
					                      enum FUNC_EVENT event);

/* This data structure is used to store the information of fuction services 
 * that are registered with the base layer driver */

typedef struct __pmc_ntb_func {

    struct list_head  list;           /* Linked list for maintaining the list of functions */
    u32               DSID;           /* Function service ID */
    void              *func_data;     /* Function service's data */
    unsigned long     mem_size;       /* I/O memory size for the function */
    unsigned long     buf_size;       /* Buffer size for the function */
    pmc_ntb_ipc_event_cb ipc_event_cb; /* Event callback for function layer driver synchronization with remote EPs function layer service */
    pmc_ntb_frame_receive_cb frame_receive_cb; /* Callback function to send the received frame to function service */
    pmc_ntb_func_rx_cb func_rx_cb; /* Callback function to send the received frame to application */
    u8                func_init_done; /* Flag to check if function service init is done or not */
} pmc_ntb_func;


typedef struct _ses_inquiry_input_data{
	u8	opcode;
	u8	evpd;
	u8 	pagecode;
	u8	offset_msb;
	u8	offset_lsb;
	u8	alloc_len_msb;
	u8	alloc_len_lsb;
}ses_inquiry_input_data;

typedef struct _ses_inquiry_output_data{
	u8	opcode;
	u8	pagecode;
	u16 	data_len;
	u8	offset_msb;
	u8	offset_lsb;
	u16	total_len;
	u8	data[1016];
}ses_inquiry_output_data;

typedef struct _ses_tur_input_data{
	u8	opcode;
	u32	reserved;
}ses_tur_input_data;

typedef struct _ses_recv_diag_input_data{
	u8	opcode;
	u8	pagecode;
	u16	reserved;
	u8	offset_msb;
	u8    offset_lsb;
	u8	alloc_len_msb;
	u8    alloc_len_lsb;
}ses_recv_diag_input_data;

typedef struct _ses_recv_diag_output_data{
	u8	opcode;
	u8	pagecode;
	u16	data_len;
	u8	offset_msb;
	u8    offset_lsb;
	u16	total_len;
	u8	data[1016];
}ses_recv_diag_output_data;

typedef struct _ses_send_diag_input_data{
	u8	opcode;
	u8	pagecode;
	u8	data_len_msb;
	u8    data_len_lsb;
	u8	offset_msb;
	u8	offset_lsb;
	u8	total_len_msb;
	u8    total_len_lsb; 
	u8	data[1016];
}ses_send_diag_input_data;


extern pmc_ntb_global ep_tree_root;
extern u32 ntb_ibmsg_off[IPC_MSG_MAX];
extern u32 ntb_ibmsg_sts_msk_sp_off[IPC_MSG_MAX];
extern u32 ntb_ibmsgsp_off[IPC_MSG_MAX];
extern u32 ntb_ibmsgsts_off[IPC_MSG_MAX];
extern u32 ntb_ibmsgsts_msk_off[IPC_MSG_MAX];
extern u32 ntb_obmsg_off[IPC_MSG_MAX];
extern u32 ntb_obmsg_map_off[IPC_MSG_MAX];
extern u32 ntb_obmsg_sts_off[IPC_MSG_MAX];

extern unsigned long buf_pool_size[BUF_POOL_MAX];
extern int system_id;

extern u64 ntb_ipc_valid_mask[NTB_MAX];
extern u64 ntb_ipc_done_mask[NTB_MAX];
extern u64 ntb_ipc_fs_mask[NTB_MAX];
extern u64 ntb_ipc_pkt_mask[NTB_MAX];


#endif /* __CLS_SG_H__ */

