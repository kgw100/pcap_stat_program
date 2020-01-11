#include <header/sfdafx.h>
#include <header/stat.h>

void EnpSrc_stat(Enp_HashMap & Enp_HM, string key, struct pcap_pkthdr* cap_pac)
{
    if(!Enp_HM.count(key)){//"count()" is more convenient than "find()"!
        Enp_HM[key] = vector <uint32_t> {0,0,0,0};
        Enp_HM[key][0]+= 1;
        Enp_HM[key][1]+= cap_pac->len;
    }
    else {

        Enp_HM[key][0]+= 1;
        Enp_HM[key][1]+= cap_pac->len;
    }
}
void EnpDst_stat(Enp_HashMap & Enp_HM, string key, struct pcap_pkthdr* cap_pac)
{
    if(!Enp_HM.count(key)){
        Enp_HM[key] = vector <uint32_t> {0,0,0,0};
        Enp_HM[key][2]+= 1;
        Enp_HM[key][3]+= cap_pac->len;
    }
    else {
        Enp_HM[key][2]+= 1;
        Enp_HM[key][3]+= cap_pac->len;
    }
}
void Cov_stat(Cov_HashMap & Cov_HM, string A, string B, struct pcap_pkthdr* cap_pac)
{
    key_pair kp_sd = key_pair(A,B);
//    cout << kp_sd.first <<" "<< kp_sd.second<<endl;
    key_pair kp_ds = key_pair(B,A);
    uint8_t check_sd = Cov_HM.count(kp_sd);
    uint8_t check_ds = Cov_HM.count(kp_ds);

    if (check_sd == 0 && check_ds ==0){
        Cov_HM[kp_sd] = vector <uint32_t> {0,0,0,0};
        Cov_HM[kp_sd][0]+= 1;
        Cov_HM[kp_sd][1]+= cap_pac->len;
    }
    else if(check_sd != 0 && check_ds == 0){
        Cov_HM[kp_sd][0]+= 1;
        Cov_HM[kp_sd][1]+= cap_pac->len;
    }
    else{ //(check_sd == 0 && check_ds != 0)
            Cov_HM[kp_ds][2]+= 1;
            Cov_HM[kp_ds][3]+= cap_pac->len;
    }
}
void stat_print(Enp_HashMap Enp_HM, Cov_HashMap Cov_HM){
    int num;
    intro();
    do{
        cout << "Select number:";
        cin  >> num;

    switch (num) {
    case 1:
        cout << "ENDPOINT Ethernet-----------------------------"<<endl;
        cout << "Address\t\t  Packets Tx_Packets Tx_Byte Rx_Packets Rx_Byte"<<endl;
        for (pair<string,vector<uint32_t>> vh: Enp_HM) {
            if(vh.first.size()==mac_strsz)
            cout << vh.first <<" |\t"<<vh.second[0]+vh.second[2]<< "\t" << vh.second[0]<<"\t"<< vh.second[1]<<"\t"<<vh.second[2]<<"\t"<<vh.second[3]<<endl;
        }
        break;
    case 2:
        cout << "ENDPOINT IPv4---------------------------------"<<endl;
        cout << "Address    Packets Tx_Packets Tx_Byte Rx_Packets Rx_Byte"<<endl;
        for (pair<string,vector<uint32_t>> vh: Enp_HM) {
            if(vh.first.size()!=mac_strsz)
            cout << vh.first <<"\t"<<vh.second[0]+vh.second[2]<< "\t" << vh.second[0]<<"\t"<< vh.second[1]<<"\t"<<vh.second[2]<<"\t"<<vh.second[3]<<endl;
        }
        break;
    case 3:
        cout << "CONVERSATION Ethernet-------------------------"<<endl;
        cout << "Address[A]\t\t  Address[B]\t   Packets Packets[A->B] Bytes[A->B] Packets[B->A] Byte[B->A]"<<endl;
        for (auto const &entry: Cov_HM)
        {
            auto key_pair = entry.first;
            auto value = entry.second;
            if(key_pair.first.size()==mac_strsz)
            cout<< key_pair.first <<"\t" <<key_pair.second <<"\t"<<value[0]+value[2]<<"\t"<<value[0]<<"\t  "<<value[1]<<"\t\t"<<value[2]<<"\t\t"<<value[3]<<endl;
        }
        break;
    case 4:
        cout << "CONVERSATION Ipv4-----------------------------"<<endl;
        cout << "Address[A]\t  Address[B]\t   Packets Packets[A->B] Bytes[A->B] Packets[B->A] Byte[B->A]"<<endl;
        for (auto const &entry: Cov_HM)
        {
            auto key_pair = entry.first;
            auto value = entry.second;
            if(key_pair.first.size()!=mac_strsz)
            cout<< key_pair.first <<"\t" <<key_pair.second <<"\t     "<<value[0]+value[2]<<"\t\t "<<value[0]<<"\t    "<<value[1]<<"\t\t "<<value[2]<<"\t\t"<<value[3]<<endl;
        }
        break;
    case 5: cout<<"Program end!"<<endl;
            cout<<"Thank you! :)"<<endl;
            exit(EXIT_SUCCESS);
    default: cout<<"Invalid number! Please enter a number again."<<endl;
             cin.clear();
             cin.ignore(256,'\n');
             intro();
             break;
        }

    }while(true);
}

void intro(){
    cout << "\t\t\t[[Packets Stastistic Program]]\n";
    cout << "*Memu"<<endl;
    cout << "----------------------------------------------"<<endl;
    cout << "1. Endpoint Ethernet statistic"<<endl;
    cout << "2. Endpoint Ip4 statistic"<<endl;
    cout << "3. Conversation Enthernet statistic"<<endl;
    cout << "4. Conversation Ip4 statistic"<<endl;
    cout << "5. exit"<<endl;

}