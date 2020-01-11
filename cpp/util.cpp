#include <header/util.h>


void usage() {
  printf("syntax: pcap_stat <pcap file name> \n");
  printf("sample: pcap_stat pcap_file_test.pcap \n");
}
void tohex(const u_char * in, size_t insz, char * out, size_t outsz)
{
    const u_char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for (; pin< in + insz; pout += 3 , pin ++)
    {
        pout[0] = hex[(*pin>>4)&0xF];
        pout[1] = hex[*pin & 0XF];
        pout[2] = ':';
        if(pout + 3- out > outsz){
            break; //prevent buffer overflow
        }
    }
    pout[-1] = 0;
}



