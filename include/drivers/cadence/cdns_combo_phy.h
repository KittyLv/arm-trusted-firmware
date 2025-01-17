/*
 * Copyright (c) 2022, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2022-2023, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CDN_COMBOPHY_H
#define CDN_COMBOPHY_H

/* SRS */
#define SDMMC_CDN_SRS02		0x8
#define SDMMC_CDN_SRS03		0xC
#define SDMMC_CDN_SRS04		0x10
#define SDMMC_CDN_SRS05		0x14
#define SDMMC_CDN_SRS06		0x18
#define SDMMC_CDN_SRS07		0x1C
#define SDMMC_CDN_SRS09		0x24
#define SDMMC_CDN_SRS10		0x28
#define SDMMC_CDN_SRS11		0x2C
#define SDMMC_CDN_SRS12		0x30
#define SDMMC_CDN_SRS13		0x34
#define SDMMC_CDN_SRS14		0x38

/* SRS03 */
#define RTS		16
#define CRCCE		19
#define CIDX		24

/* SRS09 */
#define CI		16

/* SRS10 */
#define DTW		1
#define EDTW		5
#define BP		8
#define BVS		9

/* SRS11 */
#define ICE		0
#define ICS		1
#define SDCE		2
#define USDCLKFS	6
#define SDCLKFS		8
#define DTCV		16

/* SRS12 */
#define CC		0
#define TC		1
#define EINT		15

/* SRS14 */
#define CC_IE		0
#define TC_IE		1
#define DMAINT_IE	3

/* Combo PHY DLL registers */
#define CP_DLL_REG_BASE				(0x10B92000)
#define CP_DLL_DQ_TIMING_REG		(0x00)
#define CP_DLL_DQS_TIMING_REG		(0x04)
#define CP_DLL_GATE_LPBK_CTRL_REG	(0x08)
#define CP_DLL_MASTER_CTRL_REG		(0x0C)
#define CP_DLL_SLAVE_CTRL_REG		(0x10)
#define CP_DLL_IE_TIMING_REG		(0x14)

#define CP_DQ_TIMING_REG_SDR 		(0x00000002)
#define CP_DQS_TIMING_REG_SDR 		(0x00100004)
#define CP_GATE_LPBK_CTRL_REG_SDR 	(0x00D80000)
#define CP_DLL_MASTER_CTRL_REG_SDR 	(0x00800000)
#define CP_DLL_SLAVE_CTRL_REG_SDR 	(0x00000000)

#define CP_DLL(_reg)				(CP_DLL_REG_BASE \
									+ (CP_DLL_##_reg))

/* Control Timing Block registers */
#define CP_CTB_REG_BASE			(0x10B92080)
#define CP_CTB_CTRL_REG			(0x00)
#define CP_CTB_TSEL_REG			(0x04)
#define CP_CTB_GPIO_CTRL0		(0x08)
#define CP_CTB_GPIO_CTRL1		(0x0C)
#define CP_CTB_GPIO_STATUS0		(0x10)
#define CP_CTB_GPIO_STATUS1		(0x14)

#define CP_CTRL_REG_SDR 		(0x00004040)
#define CP_TSEL_REG_SDR 		(0x00000000)

#define CP_CTB(_reg)			(CP_CTB_REG_BASE \
								+ (CP_CTB_##_reg))

/* Combo PHY */
#define SDMMC_CDN_REG_BASE		0x10808200
#define PHY_DQ_TIMING_REG		0x2000
#define PHY_DQS_TIMING_REG		0x2004
#define PHY_GATE_LPBK_CTRL_REG		0x2008
#define PHY_DLL_MASTER_CTRL_REG		0x200C
#define PHY_DLL_SLAVE_CTRL_REG		0x2010
#define PHY_CTRL_REG			0x2080
#define PHY_REG_ADDR_MASK		0xFFFF
#define PHY_REG_DATA_MASK		0xFFFFFFFF

/* PHY_DQS_TIMING_REG */
#define CP_USE_EXT_LPBK_DQS(x)		((x) << 22) //0x1
#define CP_USE_LPBK_DQS(x)		((x) << 21) //0x1
#define CP_USE_PHONY_DQS(x)		((x) << 20) //0x1
#define CP_USE_PHONY_DQS_CMD(x)		((x) << 19) //0x1

/* PHY_GATE_LPBK_CTRL_REG */
#define CP_SYNC_METHOD(x)		((x) << 31) //0x1
#define CP_SW_HALF_CYCLE_SHIFT(x)	((x) << 28) //0x1
#define CP_RD_DEL_SEL(x)		((x) << 19) //0x3f
#define CP_UNDERRUN_SUPPRESS(x)		((x) << 18) //0x1
#define CP_GATE_CFG_ALWAYS_ON(x)	((x) << 6) //0x1

/* PHY_DLL_MASTER_CTRL_REG */
#define CP_DLL_BYPASS_MODE(x)		((x) << 23) //0x1
#define CP_DLL_START_POINT(x)		((x) << 0) //0xff

/* PHY_DLL_SLAVE_CTRL_REG */
#define CP_READ_DQS_CMD_DELAY(x)	((x) << 24) //0xff
#define CP_CLK_WRDQS_DELAY(x)		((x) << 16) //0xff
#define CP_CLK_WR_DELAY(x)		((x) << 8) //0xff
#define CP_READ_DQS_DELAY(x)		((x) << 0) //0xff

/* PHY_DQ_TIMING_REG */
#define CP_IO_MASK_ALWAYS_ON(x)		((x) << 31) //0x1
#define CP_IO_MASK_END(x)		((x) << 27) //0x7
#define CP_IO_MASK_START(x)		((x) << 24) //0x7
#define CP_DATA_SELECT_OE_END(x)	((x) << 0) //0x7

/* PHY_CTRL_REG */
#define CP_PHONY_DQS_TIMING_MASK	0x3F
#define CP_PHONY_DQS_TIMING_SHIFT	4

/* Shared Macros */
#define SDMMC_CDN(_reg)		(SDMMC_CDN_REG_BASE + \
					(SDMMC_CDN_##_reg))

struct cdns_sdmmc_combo_phy {
	uint32_t	cp_clk_wr_delay;
	uint32_t	cp_clk_wrdqs_delay;
	uint32_t	cp_data_select_oe_end;
	uint32_t	cp_dll_bypass_mode;
	uint32_t	cp_dll_locked_mode;
	uint32_t	cp_dll_start_point;
	uint32_t	cp_gate_cfg_always_on;
	uint32_t	cp_io_mask_always_on;
	uint32_t	cp_io_mask_end;
	uint32_t	cp_io_mask_start;
	uint32_t	cp_rd_del_sel;
	uint32_t	cp_read_dqs_cmd_delay;
	uint32_t	cp_read_dqs_delay;
	uint32_t	cp_sw_half_cycle_shift;
	uint32_t	cp_sync_method;
	uint32_t	cp_underrun_suppress;
	uint32_t	cp_use_ext_lpbk_dqs;
	uint32_t	cp_use_lpbk_dqs;
	uint32_t	cp_use_phony_dqs;
	uint32_t	cp_use_phony_dqs_cmd;
};

/* Function Prototype */

int cdns_sdmmc_write_phy_reg(uint32_t phy_reg_addr, uint32_t phy_reg_addr_value,
			uint32_t phy_reg_data, uint32_t phy_reg_data_value);
int cdns_sd_card_detect(void);
int cdns_emmc_card_reset(void);

#endif
