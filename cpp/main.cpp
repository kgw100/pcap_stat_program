#include <header/sfdafx.h>
#include <header/util.h>
#include <header/pcap_stat.h>


int main(int argc, const char* argv[])
{
    //check parameter
    if(argc != 2) {
        usage();
        return -1;
        }
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file_name = argv[1];
    pcap_t * handle = (pcap_t *)malloc(sizeof(pcap_t *));
    pcap_pkthdr* header= (pcap_pkthdr *)malloc(sizeof(pcap_pkthdr));
    const u_char* packet =(u_char *)malloc(sizeof(u_char));

    handle = pcap_open_offline(argv[1],errbuf);
    if (handle == nullptr){  //file open error
      fprintf(stderr, "couldn't open file %s: %s \n", file_name, errbuf);
      return -1;
    }
    //hashmap declare
    Enp_HashMap Enp_HM;
   // unordered_map<pair<string,string>,vector<uint32_t>> Cov_HM; //compile error
    Cov_HashMap Cov_HM; //compile success!

    while (true){ // main_process
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) // -1 error / -2 eof
          break;

        uint16_t eth_type = uint16_t((packet[12]<<8)|packet[13]);
        uint pac_len = header->len;
        //calculate Ethernet Statistical data
        Eth_stat(Enp_HM,Cov_HM,pac_len, packet);
        //calculate Ivp4 Statistical data
        if(eth_type == ip4_type) Ip_stat(Enp_HM,Cov_HM,pac_len,packet);
        }
    free(header); free((void *)packet); free(handle);
    header =nullptr; packet =nullptr; handle =nullptr;

    //print result
    stat_print(Enp_HM,Cov_HM);
    }
