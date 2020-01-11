#pragma once
#include <arpa/inet.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <utility>
#include <ostream>
#include <pcap.h>
#include <unordered_map>
#include <vector>

#define mac_strsz 17
#define mac_addrSize 6
#define ip4_type 0x0800

using namespace std;
//typedef pair<string, string> pair;

struct pair_hash {
    //pair_hash is possible,
    //but there is some potential for collision
    template<class T1, class T2>
    size_t operator () (const pair<T1,T2> &p) const{
        auto h1 = hash<T1>{}(p.first);
        auto h2 = hash<T2>{}(p.second);

//        return h1 ^ h2; //original
        return h1 ^ (h2 << 1); // hash collsion improving
    }
};


using key_pair = pair<string,string>;
using Enp_HashMap = unordered_map<string,vector<uint32_t>>;
using Cov_HashMap = unordered_map<key_pair,vector<uint32_t>,pair_hash>;
