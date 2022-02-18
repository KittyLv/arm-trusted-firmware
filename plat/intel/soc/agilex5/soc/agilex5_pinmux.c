/*
 * Copyright (c) 2019-2022, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <lib/mmio.h>

#include "agilex5_pinmux.h"
#include "agilex5_system_manager.h"

const uint32_t sysmgr_pinmux_array_sel[] = {
	0x00000000, 0x00000001, /* usb */
	0x00000004, 0x00000001,
	0x00000008, 0x00000001,
	0x0000000c, 0x00000001,
	0x00000010, 0x00000001,
	0x00000014, 0x00000001,
	0x00000018, 0x00000001,
	0x0000001c, 0x00000001,
	0x00000020, 0x00000001,
	0x00000024, 0x00000001,
	0x00000028, 0x00000001,
	0x0000002c, 0x00000001,
	0x00000030, 0x00000000, /* emac0 */
	0x00000034, 0x00000000,
	0x00000038, 0x00000000,
	0x0000003c, 0x00000000,
	0x00000040, 0x00000000,
	0x00000044, 0x00000000,
	0x00000048, 0x00000000,
	0x0000004c, 0x00000000,
	0x00000050, 0x00000000,
	0x00000054, 0x00000000,
	0x00000058, 0x00000000,
	0x0000005c, 0x00000000,
	0x00000060, 0x00000008, /* gpio1 */
	0x00000064, 0x00000008,
	0x00000068, 0x00000005,  /* uart0 tx */
	0x0000006c, 0x00000005,  /*  uart 0 rx */
	0x00000070, 0x00000008,  /*  gpio */
	0x00000074, 0x00000008,
	0x00000078, 0x00000004, /* i2c1 */
	0x0000007c, 0x00000004,
	0x00000080, 0x00000007,  /* jtag */
	0x00000084, 0x00000007,
	0x00000088, 0x00000007,
	0x0000008c, 0x00000007,
	0x00000090, 0x00000001,  /* sdmmc data0 */
	0x00000094, 0x00000001,
	0x00000098, 0x00000001,
	0x0000009c, 0x00000001,
	0x00000100, 0x00000001,
	0x00000104, 0x00000001,  /* sdmmc.data3 */
	0x00000108, 0x00000008,  /* loan */
	0x0000010c, 0x00000008,   /* gpio */
	0x00000110, 0x00000008,
	0x00000114, 0x00000008,  /* gpio1.io21 */
	0x00000118, 0x00000005,  /* mdio0.mdio */
	0x0000011c, 0x00000005  /* mdio0.mdc */
};

const uint32_t sysmgr_pinmux_array_ctrl[] = {
	0x00000000, 0x00502c38, /* Q1_1 */
	0x00000004, 0x00102c38,
	0x00000008, 0x00502c38,
	0x0000000c, 0x00502c38,
	0x00000010, 0x00502c38,
	0x00000014, 0x00502c38,
	0x00000018, 0x00502c38,
	0x0000001c, 0x00502c38,
	0x00000020, 0x00502c38,
	0x00000024, 0x00502c38,
	0x00000028, 0x00502c38,
	0x0000002c, 0x00502c38,
	0x00000030, 0x00102c38, /* Q2_1 */
	0x00000034, 0x00102c38,
	0x00000038, 0x00502c38,
	0x0000003c, 0x00502c38,
	0x00000040, 0x00102c38,
	0x00000044, 0x00102c38,
	0x00000048, 0x00502c38,
	0x0000004c, 0x00502c38,
	0x00000050, 0x00102c38,
	0x00000054, 0x00102c38,
	0x00000058, 0x00502c38,
	0x0000005c, 0x00502c38,
	0x00000060, 0x00502c38, /* Q3_1 */
	0x00000064, 0x00502c38,
	0x00000068, 0x00102c38,
	0x0000006c, 0x00502c38,
	0x000000d0, 0x00502c38,
	0x000000d4, 0x00502c38,
	0x000000d8, 0x00542c38,
	0x000000dc, 0x00542c38,
	0x000000e0, 0x00502c38,
	0x000000e4, 0x00502c38,
	0x000000e8, 0x00102c38,
	0x000000ec, 0x00502c38,
	0x000000f0, 0x00502c38, /* Q4_1 */
	0x000000f4, 0x00502c38,
	0x000000f8, 0x00102c38,
	0x000000fc, 0x00502c38,
	0x00000100, 0x00502c38,
	0x00000104, 0x00502c38,
	0x00000108, 0x00102c38,
	0x0000010c, 0x00502c38,
	0x00000110, 0x00502c38,
	0x00000114, 0x00502c38,
	0x00000118, 0x00542c38,
	0x0000011c, 0x00102c38
};

const uint32_t sysmgr_pinmux_array_fpga[] = {
	0x00000000, 0x00000000,
	0x00000004, 0x00000000,
	0x00000008, 0x00000000,
	0x0000000c, 0x00000000,
	0x00000010, 0x00000000,
	0x00000014, 0x00000000,
	0x00000018, 0x00000000,
	0x0000001c, 0x00000000,
	0x00000020, 0x00000000,
	0x00000028, 0x00000000,
	0x0000002c, 0x00000000,
	0x00000030, 0x00000000,
	0x00000034, 0x00000000,
	0x00000038, 0x00000000,
	0x0000003c, 0x00000000,
	0x00000040, 0x00000000,
	0x00000044, 0x00000000,
	0x00000048, 0x00000000,
	0x00000050, 0x00000000,
	0x00000054, 0x00000000,
	0x00000058, 0x0000002a
};

const uint32_t sysmgr_pinmux_array_iodelay[] = {
	0x00000000, 0x00000000,
	0x00000004, 0x00000000,
	0x00000008, 0x00000000,
	0x0000000c, 0x00000000,
	0x00000010, 0x00000000,
	0x00000014, 0x00000000,
	0x00000018, 0x00000000,
	0x0000001c, 0x00000000,
	0x00000020, 0x00000000,
	0x00000024, 0x00000000,
	0x00000028, 0x00000000,
	0x0000002c, 0x00000000,
	0x00000030, 0x00000000,
	0x00000034, 0x00000000,
	0x00000038, 0x00000000,
	0x0000003c, 0x00000000,
	0x00000040, 0x00000000,
	0x00000044, 0x00000000,
	0x00000048, 0x00000000,
	0x0000004c, 0x00000000,
	0x00000050, 0x00000000,
	0x00000054, 0x00000000,
	0x00000058, 0x00000000,
	0x0000005c, 0x00000000,
	0x00000060, 0x00000000,
	0x00000064, 0x00000000,
	0x00000068, 0x00000000,
	0x0000006c, 0x00000000,
	0x00000070, 0x00000000,
	0x00000074, 0x00000000,
	0x00000078, 0x00000000,
	0x0000007c, 0x00000000,
	0x00000080, 0x00000000,
	0x00000084, 0x00000000,
	0x00000088, 0x00000000,
	0x0000008c, 0x00000000,
	0x00000090, 0x00000000,
	0x00000094, 0x00000000,
	0x00000098, 0x00000000,
	0x0000009c, 0x00000000,
	0x00000100, 0x00000000,
	0x00000104, 0x00000000,
	0x00000108, 0x00000000,
	0x0000010c, 0x00000000,
	0x00000110, 0x00000000,
	0x00000114, 0x00000000,
	0x00000118, 0x00000000,
	0x0000011c, 0x00000000
};

void config_fpgaintf_mod(void)
{
	mmio_write_32(SOCFPGA_SYSMGR(FPGAINTF_EN_2), 1<<8);
}


void config_pinmux(handoff *hoff_ptr)
{
	unsigned int i;

	mmio_write_32(0xbeec, 0x7e000);
	for (i = 0; i < 96; i += 2) {
		mmio_write_32(AGX5_PINMUX_PIN0SEL +
			hoff_ptr->pinmux_sel_array[i],
			hoff_ptr->pinmux_sel_array[i+1]);
	}

	config_fpgaintf_mod();
}


void config_peripheral(handoff *hoff_ptr)
{

#if 0
	// Pending SDM to pass over handoff data
	unsigned int i;

	for (i = 0; i < 4; i += 2) {
		mmio_write_32(AGX_EDGE_PERIPHERAL +
		hoff_ptr->peripheral_pwr_gate_array[i],
		hoff_ptr->peripheral_pwr_gate_array[i+1]);
	}
#endif

	// This need to be update due to peripheral_pwr_gate_array handoff change
	mmio_write_32(AGX5_PERIPHERAL,
	hoff_ptr->peripheral_pwr_gate_array);

}
