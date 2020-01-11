#pragma once
#include <header/sfdafx.h>
#include <unordered_map>
#include <vector>

void stat_print(Enp_HashMap Enp_HM, Cov_HashMap Cov_HM);
void EnpSrc_stat(Enp_HashMap & Enp_HM, string key, struct pcap_pkthdr* cap_pac);
void EnpDst_stat(Enp_HashMap & Enp_HM, string key, struct pcap_pkthdr* cap_pac);
void Cov_stat(Cov_HashMap & Cov_HM, string A, string B, struct pcap_pkthdr* cap_pac);
void intro();
