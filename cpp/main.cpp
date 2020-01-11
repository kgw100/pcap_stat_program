#include <header/sfdafx.h>
#include <header/util.h>
#include <header/stat.h>

int main(int argc, const char* argv[])
{
    //check parameter
    if(argc != 2) {
        usage();
        return -1;
        }
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file_name = argv[1];
    pcap_t * handle = pcap_open_offline(argv[1],errbuf);

    if (handle == NULL) { //file open error
      fprintf(stderr, "couldn't open file %s: %s \n", file_name, errbuf);
      return -1;
    }
    //hashmap declare
    Enp_HashMap Enp_HM;
   // unordered_map<pair<string,string>,vector<uint32_t>> Cov_HM; //compile error
    Cov_HashMap Cov_HM; //compile success!
    in_addr sip, tip;

    while (true){ // main_process
        struct pcap_pkthdr* header;
        const u_char* packet;
        string sender_ip;
        string target_ip;
        size_t outsz= 3*mac_addrSize;
        char s_mac[outsz];
        char d_mac[outsz];
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) // -1 error / -2 eof
          break;

        uint16_t eth_type = uint16_t((packet[12]<<8)|packet[13]);
        // Get mac_address
        tohex(&packet[0],sizeof(packet),d_mac,outsz);
        tohex(&packet[6],sizeof(packet),s_mac,outsz);
        // Endpoint ethernet statistic
        EnpSrc_stat(Enp_HM,s_mac,header);
        EnpDst_stat(Enp_HM,d_mac,header);
        // Conversation ethernet statistic
        Cov_stat(Cov_HM,s_mac,d_mac,header);

        if(eth_type == ip4_type)  {
            // Get ip_address
            sip.s_addr = reinterpret_cast<uint32_t>(htonl((packet[26]<<24 )| (packet[27]<<16)| (packet[28] <<8)| packet[29]));
            tip.s_addr = reinterpret_cast<uint32_t>(htonl((packet[30]<<24 )| (packet[31]<<16)| (packet[32] <<8)| packet[33]));
            sender_ip = string(inet_ntoa(sip));
            target_ip = string(inet_ntoa(tip));
            // Endpoint ip4 statistic
            EnpSrc_stat(Enp_HM,sender_ip,header);
            EnpDst_stat(Enp_HM,target_ip,header);
            // Conversation ip4 statistic
            Cov_stat(Cov_HM,sender_ip,target_ip,header);
            }
        }
    stat_print(Enp_HM,Cov_HM);
    return 0;
    }


//old-pattern
//  unordered_map<string,list<uint32_t>>::itervhr it; //or auto it = m.begin();
//    for (it =Enp_HM.begin(); it!= Enp_HM.end(); it++){
//     cout << it->first<<"" <<it->secound <<endl;
//}

 //    for (int i=0;i<ip_lst.size();i++) {
//        ip_lst[0];
//    }

//      cout<<ip_lst.size()<<endl;

//    for (it=ip_lst.begin(); it != ip_lst.end(); ++it)
//    {
//        cout << *it << endl;
//    }

//    for (int i=0;i<4;i++) {
//    cout << Enp_HM["172.30.1.48"][i] <<endl;
//    }

//new-pattern
//for (pair<string,vector<uint32_t>> vhm: Enp_HM) {
//       cout << vhm.first << vhm. <<endl;
//}

    //         for (it= ip_lst.begin(); it != ip_lst.end();it++)
    //         {
    //             printf("%s \n",(*it).c_str());

    //         }
