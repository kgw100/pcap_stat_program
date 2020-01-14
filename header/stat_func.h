#pragma once
#include <header/sfdafx.h>
#define tx_pac 0
#define tx_byte 1
#define rx_pac 2
#define rx_byte 3

[[noreturn]]void stat_print(Enp_HashMap Enp_HM, Cov_HashMap Cov_HM);
void EnpSrc_stat(Enp_HashMap & Enp_HM, string key, uint pac_len);
void EnpDst_stat(Enp_HashMap & Enp_HM, string key, uint pac_len);
void Cov_stat(Cov_HashMap & Cov_HM, string A, string B, uint pac_len);
void intro();
