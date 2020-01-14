#include <header/sfdafx.h>
#include <header/stat_ptcs.h>
#include <header/stat_func.h>
#include <header/util.h>

void Eth_stat(Enp_HashMap & Enp_HM, Cov_HashMap & Cov_HM,uint pac_len, const u_char * packet)
{
    size_t outsz= 3*mac_addrSize;
    char * s_mac = static_cast<char *>(malloc(sizeof(char)*outsz));
    char * d_mac = static_cast<char *>(malloc(sizeof(char)*outsz));
    // Get mac_address
    tohex(&packet[0],sizeof(packet),d_mac,outsz); //u_char array to hex string
    tohex(&packet[6],sizeof(packet),s_mac,outsz); //u_char array to hex string
    // Endpoint ethernet statistic
    EnpSrc_stat(Enp_HM,s_mac,pac_len);
    EnpDst_stat(Enp_HM,d_mac,pac_len);
    // Conversation ethernet statistic
    Cov_stat(Cov_HM,s_mac,d_mac,pac_len);
}
void Ip_stat(Enp_HashMap & Enp_HM, Cov_HashMap & Cov_HM,uint pac_len, const u_char * packet)
{
     in_addr sip, tip;
     string sender_ip, target_ip;
     sip.s_addr = htonl(static_cast<uint32_t>((packet[26]<<24 )| (packet[27]<<16)| (packet[28] <<8)| packet[29]));
     tip.s_addr = htonl(static_cast<uint32_t>((packet[30]<<24 )| (packet[31]<<16)| (packet[32] <<8)| packet[33]));
     sender_ip = string(inet_ntoa(sip));
     target_ip = string(inet_ntoa(tip));
     // Endpoint ip4 statistic
      EnpSrc_stat(Enp_HM,sender_ip,pac_len);
      EnpDst_stat(Enp_HM,target_ip,pac_len);
      // Conversation ip4 statistic
      Cov_stat(Cov_HM,sender_ip,target_ip,pac_len);
}
