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


#include <linux/switchtec.h>
#include <linux/switchtec_ioctl.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <scsi/sg.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/version.h>
#include <linux/slab.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
#include <linux/uaccess.h>
#endif
#include "switchtec_sg.h"

#define SUCCESS 0
#define ERROR -1
#define MRPC_SES_PAGE 70

void stuser_set_state_sg(struct switchtec_user_sg *stuser,
			     enum mrpc_sg_state state)
{
	/* requires the mrpc_mutex to already be held when called */

	const char * const state_names[] = {
		[MRPC_SG_IDLE] = "IDLE",
		[MRPC_SG_QUEUED] = "QUEUED",
		[MRPC_SG_RUNNING] = "RUNNING",
		[MRPC_SG_DONE] = "DONE",
	};

	stuser->state = state;

	dev_dbg(&stuser->stdev->dev, "stuser state %p -> %s",
		stuser, state_names[state]);
}
void stuser_free_sg(struct kref *kref)
{
	struct switchtec_user_sg *stuser;

	stuser = container_of(kref, struct switchtec_user_sg, kref);

	dev_dbg(&stuser->stdev->dev, "%s: %p\n", __func__, stuser);

	put_device(&stuser->stdev->dev);
	kfree(stuser);
}


void stuser_put_sg(struct switchtec_user_sg *stuser)
{
	kref_put(&stuser->kref, stuser_free_sg);
}

void mrpc_cmd_submit_sg(struct switchtec_dev *stdev)
{
	/* requires the mrpc_mutex to already be held when called */
	u8 i;
	struct switchtec_user_sg *stuser;
	//int rc = SUCCESS;

	if (stdev->mrpc_busy)
			return;

	if (list_empty(&stdev->mrpc_queue))
			return;

	stuser = list_entry(stdev->mrpc_queue.next, struct switchtec_user_sg,
			    list);

	stuser_set_state_sg(stuser, MRPC_SG_RUNNING);
	stdev->mrpc_busy = 1;
	memcpy_toio(&stdev->mmio_mrpc->input_data,
		    stuser->data, stuser->data_len);
	iowrite32(stuser->cmd, &stdev->mmio_mrpc->cmd);

	for(i=0; i<100; i++) {
		msleep(100);
		stuser->status = ioread32(&stdev->mmio_mrpc->status);
		if (stuser->status != SWITCHTEC_MRPC_STATUS_INPROGRESS) {
			break;
		}
			
	}
	if (stuser->status != SWITCHTEC_MRPC_STATUS_INPROGRESS) {
		 mrpc_complete_cmd_sg(stdev);		
	}
	schedule_delayed_work(&stdev->mrpc_timeout,
			      msecs_to_jiffies(500));
}


void  mrpc_complete_cmd_sg(struct switchtec_dev *stdev)
{
	/* requires the mrpc_mutex to already be held when called */
	struct switchtec_user_sg *stuser;

	if (list_empty(&stdev->mrpc_queue))
		return;

	stuser = list_entry(stdev->mrpc_queue.next, struct switchtec_user_sg,
			    list);

	stuser->status = ioread32(&stdev->mmio_mrpc->status);
	if (stuser->status == SWITCHTEC_MRPC_STATUS_INPROGRESS)
		return;

	stuser_set_state_sg(stuser, MRPC_SG_DONE);
	stuser->return_code = 0;

	if (stuser->status != SWITCHTEC_MRPC_STATUS_DONE)
		goto out;

	stuser->return_code = ioread32(&stdev->mmio_mrpc->ret_value);
	if (stuser->return_code != 0){
		goto out;
	}
	memcpy_fromio(stuser->data, &stdev->mmio_mrpc->output_data,
		      stuser->read_len);

out:
	complete_all(&stuser->comp);
	list_del_init(&stuser->list);
	stuser_put_sg(stuser);
	stdev->mrpc_busy = 0;

	mrpc_cmd_submit_sg(stdev);
}

int mrpc_queue_cmd_sg(struct switchtec_user_sg *stuser)
{
	/* requires the mrpc_mutex to already be held when called */
	struct switchtec_dev *stdev = stuser->stdev;

	kref_get(&stuser->kref);
	stuser->read_len = sizeof(stuser->data);
	stuser_set_state_sg(stuser, MRPC_SG_QUEUED);
	init_completion(&stuser->comp);
	list_add_tail(&stuser->list, &stdev->mrpc_queue);

	mrpc_cmd_submit_sg(stdev);

	return 0;
}

int lock_mutex_and_test_alive_sg(struct switchtec_dev *stdev)
{
	if (mutex_lock_interruptible(&stdev->mrpc_mutex)) 
		return -EINTR;


	if (!stdev->alive) {
		mutex_unlock(&stdev->mrpc_mutex);
		return -ENODEV;
	}

	return 0;
}


/** scsi_status_is_good - check the status return.
 *
 * @status: the status passed up from the driver (including host and
 *          driver components)
 *
 * This returns true for known good conditions that may be treated as
 * command completed normally
 */
 inline int cls_scsi_status_is_good(int status)
{
	/*
	 * FIXME: bit0 is listed as reserved in SCSI-2, but is
	 * significant in SCSI-3.  For now, we follow the SCSI-2
	 * behaviour and ignore reserved bits.
	 */
	status &= 0xfe;
	return ((status == SAM_STAT_GOOD) ||
		(status == SAM_STAT_INTERMEDIATE) ||
		(status == SAM_STAT_INTERMEDIATE_CONDITION_MET) ||
		/* FIXME: this is obsolete in SAM-3 */
		(status == SAM_STAT_COMMAND_TERMINATED));
}

int fem_sg_completion(sg_io_hdr_t *hdr, u8 status, u8 sense_key,
				 u8 asc, u8 ascq)
{
	u8 xfer_len;
	u8 resp[DESC_FMT_SENSE_DATA_SIZE];

	if (cls_scsi_status_is_good(status)) {
		hdr->status = SAM_STAT_GOOD;
		hdr->masked_status = GOOD;
		hdr->host_status = DID_OK;
		hdr->driver_status = DRIVER_OK;
		hdr->sb_len_wr = 0;
	} else {
		hdr->status = status;
		hdr->masked_status = status >> 1;
		hdr->host_status = DID_OK;
		hdr->driver_status = DRIVER_OK;

		memset(resp, 0, DESC_FMT_SENSE_DATA_SIZE);
		resp[0] = DESC_FORMAT_SENSE_DATA;
		resp[1] = sense_key;
		resp[2] = asc;
		resp[3] = ascq;

		xfer_len = min_t(u8, hdr->mx_sb_len, DESC_FMT_SENSE_DATA_SIZE);
		hdr->sb_len_wr = xfer_len;
		if (copy_to_user(hdr->sbp, resp, xfer_len) > 0)
			return ERROR;
	}

	return 0;
}


void fem_sg_sense_check(sg_io_hdr_t *io,int sg_ret,u8* tmp_buf,int len)
{
	switch(sg_ret){
		case 0x0008A001:
		case 0x0008A002:
		case 0x0008A003:
		case 0x0008A004:
		case 0x0008A005:
			fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
			break;
		case 0x0008A006:
			fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					tmp_buf[9], tmp_buf[10],tmp_buf[11]);
			break;
		default:
			fem_sg_completion(io, SAM_STAT_GOOD, NO_SENSE, 0, 0);
			break;
	}
	


}

static ssize_t switchtec_dev_write_sg(struct file *filp,void *input_data, size_t input_size, void *output_data, size_t output_size)
{
	struct switchtec_user_sg *stuser = filp->private_data;
	struct switchtec_dev *stdev = stuser->stdev;
	int rc = SUCCESS;
	int i;


	if (stuser->state != MRPC_SG_IDLE) {
		rc = -EBADE;
		goto out;
	}

	stuser->cmd = MRPC_SES_PAGE;
	memcpy(&stuser->data, input_data, input_size);
	stuser->data_len = input_size;

	stuser_set_state_sg(stuser, MRPC_SG_RUNNING);
	stdev->mrpc_busy = 1;
	memcpy_toio(&stdev->mmio_mrpc->input_data,
		    stuser->data, stuser->data_len);
	iowrite32(stuser->cmd, &stdev->mmio_mrpc->cmd);

	for(i=0; i<1000; i++) {
		msleep(10);
		stuser->status = ioread32(&stdev->mmio_mrpc->status);
		if(stuser->status == SWITCHTEC_MRPC_STATUS_INPROGRESS){
			continue;
		}
		if (stuser->status == SWITCHTEC_MRPC_STATUS_DONE) {
			break;
		}
	}
	if(i>= 1000){
		LOG_ERR("%s: ERROR!! Sg command %d timeout, status 0x%08x \n", 
				__FUNCTION__, stuser->cmd, stuser->status);
	}
	
	stuser->return_code = ioread32(&stdev->mmio_mrpc->ret_value);
	if (stuser->return_code != 0){
		rc = stuser->return_code;
	}
	printk("i=%d,rc=%x\n",i,rc);
	memcpy(output_data, &stdev->mmio_mrpc->output_data, SWITCHTEC_MRPC_PAYLOAD_SIZE);	

out:
	stuser_set_state_sg(stuser, MRPC_SG_IDLE);
	stdev->mrpc_busy = 0;

	return rc;
}

/*default value setting for sg inquiry output data format first 8 bytes
*PERIPHERAL QUALIFIER=0
*PERIPHERAL DEVICE TYPE=0Dh
*RMB=0     LU_CONG=0   VERSION=07h  NORMACA=0   HISUP=0 
*RESPONSE DATA FORMAT=02h    ADDITIONAL LENGTH=51 
*SCCS=0  TPGS=0  3PC=0  PROTECT=0  ENCSERV=1  VS=0
*MULTIP=0 CMDQUE=1  VS=0
*/
int fem_sg_inquiry( struct file *filp, sg_io_hdr_t *io,int index)
{
	u32 			command,subcommand;
	int i; 
	u32 			ret = 0;
	unsigned char output_all[SG_OUTPUT_DATALEN] = {0xd,0x0,0x07,0x02,0x33,0x0,0x40,0x02};
	ses_inquiry_input_data ses_inq_input;
	ses_inquiry_output_data * ses_inq_output;
	int 			input_len;
	int			n;
	u16			data_len;
	u8		*tmp_buf;
	u16		total_len = 0;
	u16		tmp_len;
	u16		offset_tmp;
	unsigned char cmdp[io->cmd_len];

	LOG_INFO("fem_sg_inquiry inlen:%d,outlen:%d\n", io->cmd_len,io->dxfer_len);
	ret = copy_from_user(&cmdp[0],io->cmdp,io->cmd_len);
	//add new input type for ses
	command = MRPC_SES_PAGE |(1<<16);
	subcommand = SG_INQUIRY_OPCODE;
	
	ses_inq_input.opcode = SG_INQUIRY_OPCODE;
	ses_inq_input.evpd = cmdp[1] & 0x01;
	ses_inq_input.pagecode = cmdp[2];
	ses_inq_input.alloc_len_msb = cmdp[3];
	ses_inq_input.alloc_len_lsb = cmdp[4];
	ses_inq_input.offset_lsb = 0;
	ses_inq_input.offset_msb = 0;

	LOG_DEBUG("CDB data: %x %x %x %x %x %x %x %x\n",
		cmdp[0],cmdp[1],cmdp[2],cmdp[3],
		cmdp[4],cmdp[5],cmdp[6],cmdp[7]);	
	input_len = sizeof(ses_inq_input);

	tmp_buf  = kmalloc(SWITCHTEC_MRPC_PAYLOAD_SIZE*sizeof(tmp_buf),GFP_KERNEL);
	if(tmp_buf == NULL){
		LOG_ERR("kmalloc failed sg_inquiry!!\n");
		fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					NOT_READY, SCSI_ASC_WARNING,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
		return ERROR;
	}

	ret = switchtec_dev_write_sg(filp, (void *)(&ses_inq_input), input_len, tmp_buf, io->dxfer_len);
	/*CDB check , if failed , return sense data to user*/
	LOG_DEBUG("tmp_buf: %x %x %x %x %x %x %x %x\n",
		tmp_buf[0],tmp_buf[1],tmp_buf[2],tmp_buf[3],
		tmp_buf[4],tmp_buf[5],tmp_buf[6],tmp_buf[7]);
	if(ret != SUCCESS ){
		LOG_ERR("inquiry ret failed!! ret=%x\n",ret);
		fem_sg_sense_check(io,ret,tmp_buf,io->dxfer_len);
		LOG_ERR("INQUERY failed!\n");	
		return 0;
	}
	
	if(tmp_buf != NULL){
		ses_inq_output = (ses_inquiry_output_data *)tmp_buf;
		tmp_len = ses_inq_output->total_len;
		total_len |= ((0xff00 & tmp_len)>>8);
		total_len |=((0x00ff & tmp_len)<<8);
		LOG_INFO("inquiry output is not NULL!! totallen=%d\n",total_len);
		n = total_len / SG_RAW_DATALEN;
		data_len = total_len % SG_RAW_DATALEN;
		if(total_len != 0 && n <5){
			LOG_INFO("inquiry output n=%d,total_len=%d!!\n",n,total_len);

			//there is only one page less than 1016			
			if(n == 0){
				memcpy(&output_all[8], &ses_inq_output->data[0], data_len);
			}else{
			//there are more than 1 page from FW
				memcpy(&output_all[8],&ses_inq_output->data[0], SG_RAW_DATALEN);

				for(i=1; i<=n; i++){
				 	offset_tmp = i*SG_RAW_DATALEN;
					ses_inq_input.offset_msb = (offset_tmp & 0xff00)>>8; 
					ses_inq_input.offset_lsb = offset_tmp & 0x00ff;
					if(ret != SUCCESS){
						LOG_INFO("inquiry ret failed!! ret=%x\n",ret);
						fem_sg_sense_check(io,ret,tmp_buf,io->dxfer_len);
					}
					if(tmp_buf != NULL){
						LOG_INFO("inquiry output is not NULL!!\n");
						ses_inq_output = (ses_inquiry_output_data *)tmp_buf;
						if(i == n){
							memcpy(&output_all[i*SG_RAW_DATALEN + 8], &ses_inq_output->data[0], data_len);
						}else{
							memcpy(&output_all[i*SG_RAW_DATALEN + 8], &ses_inq_output->data[0], SG_RAW_DATALEN);
						}
					}else{
						LOG_INFO("inquiry output is NULL!!\n");
					}
				}
					}
			}else{
			LOG_ERR("inquiry total len is 0!! or more than 4k!!\n");
		}
	}else{
		LOG_INFO("inquiry output is NULL!!\n");
	}

	if(tmp_buf != NULL && total_len != 0){
	//if evpd is 1 , check page code : 00h /80h /83h
		if(ses_inq_input.evpd == 1){
			if(ses_inq_input.pagecode == 0x0 ||ses_inq_input.pagecode == 0x80){
				//VPD page decode
				output_all[0] = 0xd;
				output_all[1] = ses_inq_input.pagecode;
				output_all[2] = 0;
				output_all[3] = data_len;
				printk(KERN_INFO "inquiry output is NULL!!data_len=%d\n",data_len);
				memcpy(&output_all[4],&ses_inq_output->data[0], data_len);
				total_len = total_len + 4;
			}else if(ses_inq_input.pagecode == 0x83){
				//unit serial number decode
				output_all[0] = 0xd;
				output_all[1] = ses_inq_input.pagecode;
				output_all[2] = 0;
				output_all[3] = data_len+12;
				//designation descriptor 1
				output_all[4] = 0;
				output_all[5] = 0;
				output_all[6] = 0;
				output_all[7] = 8;
				memcpy(&output_all[8],&ses_inq_output->data[0], 8);
				//designation descriptor 2
				output_all[16] = 0;
				output_all[17] = 0;
				output_all[18] = 0;
				output_all[19] = 8;
				memcpy(&output_all[20],&ses_inq_output->data[8], 8);
				total_len = total_len + 12;
			}
		}

		ret = copy_to_user(io->dxferp, &output_all[0], total_len);
		printk(KERN_INFO "inquiry copy to user done!!\n");
	}

	kfree(tmp_buf);
	return ret;
}

int fem_sg_test_unit_ready(struct file *filp, sg_io_hdr_t *io,int index)
{

	u32 			command,subcommand;
	u32 			ret = 0;
	ses_tur_input_data ses_tur_input;
	int 			input_len;
	u8*			tmp_buf;

	tmp_buf  = kmalloc(SWITCHTEC_MRPC_PAYLOAD_SIZE*sizeof(tmp_buf),GFP_KERNEL);
	if(tmp_buf == NULL){
		LOG_INFO("kmalloc failed sg_inquiry!!\n");
		fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					NOT_READY, SCSI_ASC_WARNING,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
		return ERROR;
	}

	/* DUMP input */
	LOG_INFO("sg_turs inlen:%d,outlen:%d\n", io->cmd_len,io->dxfer_len);
	command = MRPC_SES_PAGE |(1<<16);
	subcommand = SG_TURS_OPCODE;
	
	ses_tur_input.opcode = SG_TURS_OPCODE;
	ses_tur_input.reserved = 0;
	input_len = sizeof(ses_tur_input);
	ret = switchtec_dev_write_sg(filp, (void *)(&ses_tur_input), input_len, tmp_buf, io->dxfer_len);
	if(ret != SUCCESS){
		LOG_ERR("TEST UNIT READY failed!\n rt=%x\n",ret);
		fem_sg_sense_check(io,ret,(u8 *)tmp_buf,io->dxfer_len);
		return ret;
	}
	fem_sg_completion(io, SAM_STAT_GOOD, NO_SENSE, 0, 0);

	return ret;
}

int fem_sg_send_diagnostic(struct file *filp, sg_io_hdr_t *io,int index)
{
	int i; 
	u32 			command,subcommand;
	u32 			ret = 0;
	ses_send_diag_input_data  ses_send_input;
	int 		n,input_len;
	int 		data_len,total_len;
	u16 		input_datalen;
	u16		tmp_len;
	u16		offset_tmp;
	unsigned char input_data[SG_OUTPUT_DATALEN];
	unsigned char cmdp[io->cmd_len];
	unsigned char	dxferp[io->dxfer_len];	
	u8		*tmp_buf;
	
	LOG_INFO("sg_send inlen:%d,outlen:%d\n", io->cmd_len,io->dxfer_len);
	ret = copy_from_user(&cmdp[0],io->cmdp,io->cmd_len);
	ret = copy_from_user(&dxferp[0],io->dxferp,io->dxfer_len);
	
	//add new input type for ses
	command = MRPC_SES_PAGE |(1<<16);
	subcommand = SG_SEND_OPCODE;
	total_len = io->dxfer_len;
	n = total_len/SG_RAW_DATALEN;
	data_len = total_len%SG_RAW_DATALEN;

	ses_send_input.opcode = SG_SEND_OPCODE;
	ses_send_input.pagecode = dxferp[0];
	ses_send_input.total_len_msb = cmdp[3];
	ses_send_input.total_len_lsb = cmdp[4];
	input_len = 1024;

	memcpy(&input_data[0], dxferp, total_len);                          

	tmp_buf  = kmalloc(SWITCHTEC_MRPC_PAYLOAD_SIZE*sizeof(tmp_buf),GFP_KERNEL);
	if(tmp_buf == NULL){
		LOG_ERR("kmalloc failed sg_recv!!\n");
		fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					NOT_READY, SCSI_ASC_WARNING,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
		return ERROR;
	}

	for(i=0;i<=n;i++){	
		LOG_INFO("sg_send packet num=%d\n",i);
		if(i<n){
			input_datalen = tmp_len = SG_RAW_DATALEN;
			ses_send_input.data_len_msb = (u8)((tmp_len & 0xff00) >> 8);
			ses_send_input.data_len_lsb =  (u8)(tmp_len & 0xff);
		}else{
			input_datalen = tmp_len = data_len;
			ses_send_input.data_len_msb = (u8)((tmp_len& 0xff00) >> 8);
			ses_send_input.data_len_lsb =  (u8)(tmp_len & 0xff);
		}		
		offset_tmp = i*SG_RAW_DATALEN;
		ses_send_input.offset_msb = (offset_tmp & 0xff00)>>8;
		ses_send_input.offset_lsb = offset_tmp & 0xff;
		memcpy(ses_send_input.data, &input_data[i*SG_RAW_DATALEN], input_datalen);
		ret = switchtec_dev_write_sg(filp, (void *)(&ses_send_input), input_len, tmp_buf, io->dxfer_len);
		if(ret != SUCCESS){
			LOG_INFO("SEND DIAGNOSTIC failed!\n");
			break;
		}else {
 			LOG_INFO("SEND DIAGNOSTIC %d succeed!\n",i);
		}
	}
	
	if(ret != SUCCESS){
		fem_sg_sense_check(io,ret,(u8 *)tmp_buf,input_len);
	}else{
		fem_sg_completion(io, SAM_STAT_GOOD, NO_SENSE, 0, 0);
	}

	kfree(tmp_buf);
	return ret;

}

int fem_sg_recv_diagnostic(struct file *filp, sg_io_hdr_t *io,int index)
{
	int i; 
	unsigned char output_all[SG_OUTPUT_DATALEN];
	u32 			command,subcommand;
	u32 			ret = 0;
	ses_recv_diag_input_data  ses_recv_input;
	ses_recv_diag_output_data * ses_recv_output;
	int 			input_len;
	int 		n;
	int 		data_len;
	u8		*tmp_buf;
	u16		total_len = 0;
	u16		tmp_len;
	u16		offset_tmp;
	unsigned char cmdp[io->cmd_len];

	LOG_INFO("sg_recv inlen:%d,outlen:%d\n", io->cmd_len,io->dxfer_len);
	ret = copy_from_user(&cmdp[0],io->cmdp,io->cmd_len);
	/* Send command to MRPC interface */
	command = MRPC_SES_PAGE |(1<<16);
	subcommand = SG_RECV_OPCODE;

	ses_recv_input.opcode = SG_RECV_OPCODE;
	ses_recv_input.pagecode = cmdp[2];
	ses_recv_input.reserved = 0;
	ses_recv_input.offset_lsb = 0;
	ses_recv_input.offset_msb = 0;
	ses_recv_input.alloc_len_msb = cmdp[3];
	ses_recv_input.alloc_len_lsb = cmdp[4];
	input_len = sizeof(ses_recv_input);

	LOG_INFO("CDB data: %x %x %x %x %x %x %x %x\n",
		cmdp[0],cmdp[1],cmdp[2],cmdp[3],
		cmdp[4],cmdp[5],cmdp[6],cmdp[7]);	

	tmp_buf  = kmalloc(SWITCHTEC_MRPC_PAYLOAD_SIZE*sizeof(tmp_buf),GFP_KERNEL);
	if(tmp_buf == NULL){
		LOG_ERR("kmalloc failed sg_recv!!\n");
		fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					NOT_READY, SCSI_ASC_WARNING,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
		return ERROR;
	}
	ret = switchtec_dev_write_sg(filp, (void *)(&ses_recv_input), input_len, tmp_buf, io->dxfer_len);
	LOG_DEBUG("tmp_buf: %x %x %x %x %x %x %x %x\n ret=%x\n",
		tmp_buf[0],tmp_buf[1],tmp_buf[2],tmp_buf[3],
		tmp_buf[4],tmp_buf[5],tmp_buf[6],tmp_buf[7],
		ret);	
						
	if(ret != SUCCESS){
		LOG_INFO("RECEIVE DIAGNOSTIC failed!\n");
		fem_sg_sense_check(io,ret,tmp_buf,io->dxfer_len);
		kfree(tmp_buf);
		return ret;
	}
	if(tmp_buf != NULL){
		ses_recv_output = (ses_recv_diag_output_data*)tmp_buf;
		tmp_len = ses_recv_output->total_len;
		total_len |= ((0xff00 & tmp_len)>>8);
		total_len |= ((0x00ff & tmp_len)<<8);
		LOG_INFO("recv output is not NULL!! totallen=%d\n",total_len);
		n = total_len / SG_RAW_DATALEN;
		data_len = total_len % SG_RAW_DATALEN;
		if(total_len != 0 && n < 10){
			if(n == 0){
				memcpy(&output_all[0], &ses_recv_output->data[0], data_len);	
				LOG_INFO("recv outputdata: %x %x %x %x %x %x %x %x\n",
					output_all[0],output_all[1],output_all[2],output_all[3],
					output_all[4],output_all[5],output_all[6],output_all[7]);
			}else{
				memcpy(&output_all[0], &ses_recv_output->data[0], SG_RAW_DATALEN);
				for(i=1;i<=n;i++){
					offset_tmp = i*SG_RAW_DATALEN;
					ses_recv_input.offset_msb = (offset_tmp & 0xff00)>>8;
					ses_recv_input.offset_lsb = offset_tmp & 0xff;
					ret = switchtec_dev_write_sg(filp, (void *)(&ses_recv_input), input_len, tmp_buf, io->dxfer_len);
					if(ret != SUCCESS){
						LOG_INFO("RECEIVE DIAGNOSTIC failed!\n");
						fem_sg_sense_check(io,ret,tmp_buf,io->dxfer_len);
						return ret;
					}
					if((u8 *)tmp_buf != NULL){
						//LOG_INFO("recv output is not NULL!!!!!!,datalen=%d\n",data_len);
						ses_recv_output = (ses_recv_diag_output_data*)tmp_buf;
						if(i == n){
							memcpy(&output_all[i*SG_RAW_DATALEN], &ses_recv_output->data[0], data_len);
						}else{
							memcpy(&output_all[i*SG_RAW_DATALEN], &ses_recv_output->data[0], SG_RAW_DATALEN);
						}
					}else{
						LOG_DEBUG("recv output is NULL!!\n");
					}
				}
			}
		}
	}else{
		LOG_ERR("recv output is NULL or total len > 4k!!\n");
	}

	if(tmp_buf != NULL){
		ret = copy_to_user(io->dxferp, &output_all[0], total_len);
		LOG_DEBUG("ouputdata:%x %x %x %x %x %x %x %x totallen:%d\n",
			output_all[0],output_all[1],output_all[2],output_all[3],
			output_all[4],output_all[5],output_all[6],output_all[7],total_len);
		LOG_INFO("recv copy to user done!! totallen=%d\n",total_len);
	}
	fem_sg_completion(io, SAM_STAT_GOOD, NO_SENSE, 0, 0);
	kfree(tmp_buf);
	return ret;

}


int
fem_sg_io( struct file *filp, sg_io_hdr_t *io,int index)
{
	int ret;
	unsigned char cmdp[io->cmd_len];

	ret = copy_from_user(&cmdp,io->cmdp,io->cmd_len);
	
	switch(cmdp[0]){
		case 0x12:
			LOG_INFO(KERN_INFO "INQUERY");
			ret = fem_sg_inquiry(filp, io,index);
			break;
		case 0x00:
			LOG_INFO(KERN_INFO "TEST UNIT READY");
			ret = fem_sg_test_unit_ready(filp, io,index);
			break;
		case 0x1D:
			LOG_INFO(KERN_INFO "SEND DIAGNOSTIC");
			ret = fem_sg_send_diagnostic(filp, io,index);
			break;
		case 0x1C:
			LOG_INFO(KERN_INFO "RECEIVE DIAGNOSTIC");
			ret = fem_sg_recv_diagnostic(filp,io,index);
			break;
		default:
			LOG_INFO("Unsupported CDB %xh\n", cmdp[0]);
			fem_sg_completion(io, SAM_STAT_CHECK_CONDITION,
					ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB,
					SCSI_ASCQ_CAUSE_NOT_REPORTABLE);
	return -EPERM;

	}

	return ret;
}


int
fem_sg_open(struct inode *inode, 
            struct file *filp)
{
    LOG_INFO("fem_sg_open\n");
    return 0;
}

int
fem_sg_close(struct inode *inode,
             struct file *filp)
{
    LOG_INFO("fem_sg_close\n");
    return 0;
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,6))
long
fem_sg_ioctl(struct file *filp,
             unsigned int cmd_in,
             unsigned long arg)
#else
int
fem_sg_ioctl(struct inode *inode,
             struct file *filp,
             unsigned int cmd_in,
             unsigned long arg)
#endif
{
        sg_io_hdr_t io_arg;
	sg_io_hdr_t* io = &io_arg;
	const char *filename;
	int file_len;
	int index;
	int ret = 0;

    switch (cmd_in){
        case SG_IO:
            LOG_INFO("SG_IO\n");

	if(0 != copy_from_user(io,(sg_io_hdr_t *)arg, sizeof(sg_io_hdr_t))){
            		LOG_ERR("%s: Unable to copy arg from user space!\n", __FUNCTION__);
           		return -EPERM;
		}	

	    filename = filp->f_path.dentry->d_name.name;
	    file_len = strlen(filename);
	    index = filename[file_len - 1] - '0';
	    LOG_INFO("filename is %s,len is %d,index is %d\n",filename,file_len,index);
			
            fem_sg_io(filp, io,index);
	     ret = copy_to_user((sg_io_hdr_t *)arg,io,sizeof(sg_io_hdr_t));
            break;
        case SG_SET_TIMEOUT:
            LOG_INFO("SG_SET_TIMEOUT\n");
            break;
        case SG_GET_TIMEOUT:
            LOG_INFO("SG_GET_TIMEOUT\n");
            break;
        case SG_SET_FORCE_LOW_DMA:
            LOG_INFO("SG_SET_FORCE_LOW_DMA\n");
            break;
        case SG_GET_LOW_DMA:
            LOG_INFO("SG_GET_LOW_DMA\n");
            break;
        case SG_GET_SCSI_ID:
            LOG_INFO("SG_GET_SCSI_ID\n");
            break;
        case SG_SET_FORCE_PACK_ID:
            LOG_INFO("SG_SET_FORCE_PACK_ID\n");
            break;
        case SG_GET_PACK_ID:
            LOG_INFO("SG_GET_PACK_ID\n");
            break;
        case SG_GET_NUM_WAITING:
            LOG_INFO("SG_GET_NUM_WAITING\n");
            break;
        case SG_GET_SG_TABLESIZE:
            LOG_INFO("SG_GET_SG_TABLESIZE\n");
            break;
        case SG_SET_RESERVED_SIZE:
            LOG_INFO("SG_SET_RESERVED_SIZE\n");
            break;
        case SG_GET_RESERVED_SIZE:
            LOG_INFO("SG_GET_RESERVED_SIZE\n");
            break;
        case SG_SET_COMMAND_Q:
            LOG_INFO("SG_SET_COMMAND_Q\n");
            break;
        case SG_GET_COMMAND_Q:
            LOG_INFO("SG_GET_COMMAND_Q\n");
            break;
        case SG_SET_KEEP_ORPHAN:
            LOG_INFO("SG_SET_KEEP_ORPHAN\n");
            break;
        case SG_GET_KEEP_ORPHAN:
            LOG_INFO("SG_GET_KEEP_ORPHAN\n");
            break;
        case SG_NEXT_CMD_LEN:
            LOG_INFO("SG_NEXT_CMD_LEN\n");
            break;
        case SG_GET_VERSION_NUM:
            LOG_INFO("SG_GET_VERSON_NUM\n");
            break;
        case SG_GET_ACCESS_COUNT:
            LOG_INFO("SG_GET_ACCESS_COUNT\n");
            break;
        case SG_GET_REQUEST_TABLE:
            LOG_INFO("SG_GET_REQUEST_TABLE\n");
            break;
        case SG_EMULATED_HOST:
            LOG_INFO("SG_EMULATED_HOST\n");
            break;
        case SG_SET_DEBUG:
            LOG_INFO("SG_SET_DEBUG\n");
            break;
        case SG_GET_TRANSFORM:
            LOG_INFO("SG_GET_TRANSFORM\n");
            break;
        case SG_SCSI_RESET:
            LOG_INFO("SG_SCSI_RESET\n");
            break;
        default:
            LOG_INFO("Unknown SG command: %d\n", cmd_in);
            return -EPERM;
    }
    return 0;
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,6))
long
pmc_psx_ioctl(struct file *file,
                 unsigned int cmdType,
                 unsigned long arg)
#else
int 
pmc_ntb_ioctl(struct inode *inode, 
           struct file *file,
           unsigned int cmdType,
           unsigned long arg)
#endif
{
	int ret = SUCCESS;
	
       switch (cmdType) {
	case SG_SPEC_PAGE:
	{
		IOCTL io_mrpc;
		IOCTL *io = &io_mrpc;
		if(0 != copy_from_user(io,(IOCTL *)arg, sizeof(IOCTL))){
            		LOG_ERR("%s: Unable to copy arg from user space!\n", __FUNCTION__);
           		return ERROR;
		}	

		LOG_DEBUG("%s: cmd_type 0x%x cmd_id 0x%x subcmd_id 0x%x input_length %d output_length %d \n",
			__FUNCTION__, io->cmd_type, io->command, io->subcommand, io->input_length, io->output_length);

		ret = pmc_psx_spec_page_decode(file,io);
		if(ret != SUCCESS){
			LOG_ERR("%s: SG_SPEC_PAGE recv data failed!\n", __FUNCTION__);
           		return ERROR;
		}
		if(0 != copy_to_user((IOCTL *)arg, io, sizeof(IOCTL))){
			LOG_ERR("%s: Unable to copy arg to user space!\n", __FUNCTION__);
           		return ERROR;
		}
		
		break;
	}
	default:
	{
  		LOG_ERR("%s: Got illegal ioctl %d \n", __FUNCTION__, cmdType);
  		break;
	}
   }
   return ret;
}



int pmc_psx_spec_page_decode(struct file *filp,IOCTL* io)
{

		int i; 
		unsigned char output_all[SG_OUTPUT_DATALEN];
		unsigned char* input_data;
		ses_send_diag_input_data  ses_send_input;
		u32 			command,subcommand;
		u32 			ret = 0;
		ses_recv_diag_input_data ses_recv_input;
		ses_recv_diag_output_data * ses_recv_output;
		int 			input_len = 1024;
		int 			output_len = 1024;
		int 		n;
		int 		data_len;
		u8		*tmp_buf;
		u16 	total_len = 0;
		u16 	tmp_len;
		u16 	offset_tmp;

		tmp_buf  = kmalloc(SG_OUTPUT_DATALEN*sizeof(tmp_buf),GFP_KERNEL);
		if(tmp_buf == NULL){
			LOG_DEBUG("kmalloc failed pmc_psx_spec_page_decode!!\n");
			return ERROR;
		}
		
		input_data = (unsigned char*)kmalloc(SG_OUTPUT_DATALEN, GFP_KERNEL);
		if(input_data == NULL){
			LOG_ERR("kmalloc failed pmc_psx_spec_page_decode!!\n");
			kfree(tmp_buf);
			return ERROR;
		}
		LOG_DEBUG("inlen:%d,outlen:%d\n", io->input_length,io->output_length);
		/* Send command to MRPC interface */
		if((io->subcommand == 0x21 && (io->input_length != 0))
			||(io->subcommand == 0x11 && (io->input_length != 0))
			||(io->subcommand == 0x12 && (io->input_length != 0))
			||(io->subcommand == 0x13 && (io->input_length != 0))){
			ret = copy_from_user(input_data,(u8*)io->inputData,io->input_length);

			for(i=0;i<20;i++){
				LOG_DEBUG("%02x ",input_data[i]);
			}
			command = MRPC_SES_PAGE |(1<<16);
			subcommand = SG_SEND_OPCODE;
			total_len = io->input_length;
			n = total_len/SG_RAW_DATALEN;
			data_len = total_len%SG_RAW_DATALEN;

			ses_send_input.opcode = SG_SEND_OPCODE;
			ses_send_input.pagecode = io->subcommand;
			ses_send_input.total_len_msb = (io->input_length &0xff00)>>8; 
			ses_send_input.total_len_lsb = io->input_length &0xff;
			input_len = 1024;                       

			for(i=0;i<=n;i++){	
				LOG_DEBUG("sg_send packet num=%d\n",i);
				if(i<n){
					 tmp_len = SG_RAW_DATALEN;
					ses_send_input.data_len_msb = (u8)((tmp_len & 0xff00) >> 8);
					ses_send_input.data_len_lsb =  (u8)(tmp_len & 0xff);
				}else{
					tmp_len = data_len;
					ses_send_input.data_len_msb = (u8)((tmp_len& 0xff00) >> 8);
					ses_send_input.data_len_lsb =  (u8)(tmp_len & 0xff);
				}		
				offset_tmp = i*SG_RAW_DATALEN;
				ses_send_input.offset_msb = (offset_tmp & 0xff00)>>8;
				ses_send_input.offset_lsb = offset_tmp & 0xff;
				memcpy(ses_send_input.data, &input_data[i*SG_RAW_DATALEN], tmp_len);
				
				/* Send command to MRPC interface */
				ret = switchtec_dev_write_sg(filp, (void *)(&ses_send_input), input_len, tmp_buf, output_len);

				if(ret != SUCCESS){
					LOG_ERR(KERN_INFO "SEND DIAGNOSTIC failed!ret=%x\n",ret);
					io->mrpcRetVal = &ret;
					break;
				}else {
		 			LOG_DEBUG(KERN_INFO "SEND DIAGNOSTIC %d succeed!\n",i);
					ret = copy_to_user(io->outputData, tmp_buf, output_len);
					io->output_length = output_len;
					break;
				}
			}
			if(ret != SUCCESS){
				LOG_DEBUG(KERN_INFO "ret=%x return sense data\n",ret);
				ret = copy_to_user(io->outputData, tmp_buf, output_len);
			}
			io->mrpcRetVal = &ret;
			kfree(tmp_buf);
			kfree(input_data);
			return ret;
			
		}else{
			command = MRPC_SES_PAGE |(1<<16);
			subcommand = SG_RECV_OPCODE;
			ses_recv_input.opcode = SG_RECV_OPCODE;
			ses_recv_input.pagecode = io->subcommand;
			ses_recv_input.reserved = 0;
			ses_recv_input.offset_lsb = 0;
			ses_recv_input.offset_msb = 0;
			ses_recv_input.alloc_len_msb = 0xff;
			ses_recv_input.alloc_len_lsb = 0xfc;
			input_len = sizeof(ses_recv_input);

			ret = switchtec_dev_write_sg(filp, (void *)(&ses_recv_input), input_len, tmp_buf, output_len);
			
			LOG_DEBUG("tmp_buf: %x %x %x %x %x %x %x %x\n",
				tmp_buf[0],tmp_buf[1],tmp_buf[2],tmp_buf[3],
				tmp_buf[4],tmp_buf[5],tmp_buf[6],tmp_buf[7]);	

			if(ret != SUCCESS){
				LOG_ERR("RECEIVE DIAGNOSTIC failed!ret=%x return sense data\n",ret);
				ret = copy_to_user(io->outputData, tmp_buf, output_len);
				io->mrpcRetVal = &ret;
				kfree(tmp_buf);
				kfree(input_data);
				return ret;
			}
			if(tmp_buf != NULL){
				ses_recv_output = (ses_recv_diag_output_data*)tmp_buf;
				tmp_len = ses_recv_output->total_len;
				total_len |= ((0xff00 & tmp_len)>>8);
				total_len |= ((0x00ff & tmp_len)<<8);
				LOG_DEBUG("recv output is not NULL!! totallen=%d\n",total_len);
				n = total_len / SG_RAW_DATALEN;
				data_len = total_len % SG_RAW_DATALEN;
				if(total_len != 0 && n < 10){
					if(n == 0){
						memcpy(&output_all[0], &ses_recv_output->data[0], data_len);

						LOG_DEBUG("recv outputdata: %x %x %x %x %x %x %x %x\n",
							output_all[0],output_all[1],output_all[2],output_all[3],
							output_all[4],output_all[5],output_all[6],output_all[7]);
					}else{
						memcpy(&output_all[0], &ses_recv_output->data[0], SG_RAW_DATALEN);
						for(i=1;i<=n;i++){
							offset_tmp = i*SG_RAW_DATALEN;
							ses_recv_input.offset_msb = (offset_tmp & 0xff00)>>8;
							ses_recv_input.offset_lsb = offset_tmp & 0xff;
							LOG_DEBUG("\n in for before send n=%d i=%d\n",n,i);
							ret = switchtec_dev_write_sg(filp, (void *)(&ses_recv_input), input_len, tmp_buf, io->output_length);
							if(ret != SUCCESS){
								LOG_DEBUG("RECEIVE DIAGNOSTIC failed!ret=%x return sense data\n",ret);
								ret = copy_to_user(io->outputData, tmp_buf, output_len);
								io->mrpcRetVal = &ret;
								kfree(tmp_buf);
								kfree(input_data);
								return ret;
							}
							if((u8 *)tmp_buf != NULL){
								LOG_DEBUG("recv output is not NULL!!!!!!,datalen=%d\n",data_len);
								ses_recv_output = (ses_recv_diag_output_data*)tmp_buf;
								if(i == n){
									LOG_DEBUG("\n in for after send n=%d i=%d\n",n,i);
									memcpy(&output_all[i*SG_RAW_DATALEN], &ses_recv_output->data[0], data_len);
								}else{
									LOG_DEBUG("\n in for after send n=%d i=%d\n",n,i);
									memcpy(&output_all[i*SG_RAW_DATALEN], &ses_recv_output->data[0], SG_RAW_DATALEN);
								}
							}else{
								LOG_DEBUG(KERN_INFO "recv output is NULL!!\n");
							}
						}
					}
				}
			}else{
				LOG_ERR("recv output is NULL or total len > 4k!!\n");
			}
		
			if(tmp_buf != NULL){
				//memcpy(io->outputData, &output_all[0], total_len);
				ret = copy_to_user(io->outputData, &output_all[0], total_len);
				io->output_length = total_len;
				LOG_INFO("recv copy to user done!! totallen=%d\n",total_len);
			}
			kfree(tmp_buf);
			kfree(input_data);
			io->mrpcRetVal = &ret;
			return ret;
		}


}

