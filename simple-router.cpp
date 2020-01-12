/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  struct ethernet_hdr E_header;
  struct ip_hdr IP_header;
  if (packet.size() < sizeof(E_header)) {
    std::cerr << "Received packet, but the packet size is too small, ignoring" << std::endl;
    return;
  }

  memcpy(&E_header, &(packet[0]), sizeof(E_header));
  std::string MAC_broadcast = "ff:ff:ff:ff:ff:ff" ;
  std::string MAC_destination = macToString(Buffer(E_header.ether_dhost, E_header.ether_dhost+ETHER_ADDR_LEN));
  bool Is_broadcast = (MAC_broadcast == MAC_destination);
  if ( (iface != findIfaceByMac(Buffer(E_header.ether_dhost, E_header.ether_dhost+ETHER_ADDR_LEN))) && !Is_broadcast){
    return;
  }

  if (ntohs(E_header.ether_type) == ethertype_arp){
    struct arp_hdr ARP_header;
    if ( packet.size() < (sizeof(E_header) + sizeof(ARP_header)) ) {
      std::cerr << "Received packet, but the packet size is too small to contain a ARP request/reply, ignoring" << std::endl;
      return;
    }

    memcpy(&ARP_header, &(packet[sizeof(E_header)]), sizeof(ARP_header));
    if ( (ntohs(ARP_header.arp_op) == arp_op_request) && Is_broadcast ){
      if (iface->ip == ARP_header.arp_tip ){
      //original check broadcast
        Buffer ret_Packet(packet.size());
        
        memcpy(E_header.ether_dhost, E_header.ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(E_header.ether_shost, &(iface->addr[0]), sizeof(uint8_t)*ETHER_ADDR_LEN);
        ARP_header.arp_op = htons(arp_op_reply);
        ARP_header.arp_tip = ARP_header.arp_sip;
        ARP_header.arp_sip = iface->ip;
        memcpy(ARP_header.arp_tha, ARP_header.arp_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(ARP_header.arp_sha, &(iface->addr[0]), sizeof(uint8_t)*ETHER_ADDR_LEN);
        
        memcpy(&(ret_Packet[0]), &E_header, sizeof(E_header));
        memcpy(&(ret_Packet[sizeof(E_header)]), &ARP_header, sizeof(ARP_header));       
        sendPacket(ret_Packet,inIface);

        std::cerr << "arp request received, responsing arp reply..." << std::endl;
        //print_hdrs(ret_ret_Packet);
      }//original check broadcast
    }
    else if ((ntohs(ARP_header.arp_op) == arp_op_reply)  && !Is_broadcast ){
      if (iface->ip == ARP_header.arp_tip ){
        std::shared_ptr<ArpRequest> ARP_entry = m_arp.insertArpEntry(Buffer(ARP_header.arp_sha, ARP_header.arp_sha+ETHER_ADDR_LEN), ARP_header.arp_sip);
        if (ARP_entry){
          struct ethernet_hdr E_header_reply;
          E_header_reply.ether_type = htons(0x0800);
          memcpy(E_header_reply.ether_dhost, ARP_header.arp_sha, sizeof(uint8_t)*ETHER_ADDR_LEN);
          memcpy(E_header_reply.ether_shost, ARP_header.arp_tha, sizeof(uint8_t)*ETHER_ADDR_LEN);

          while(ARP_entry->packets.size() > 0){
            Buffer reply_Packet(ARP_entry->packets.front().packet.size());
            memcpy(&(reply_Packet[0]), &(ARP_entry->packets.front().packet[0]), reply_Packet.size());
            memcpy(&(reply_Packet[0]), &E_header_reply, sizeof(E_header_reply));
            sendPacket(reply_Packet, inIface);
            ARP_entry->packets.pop_front();
          }

          m_arp.removeRequest(ARP_entry);
          std::cerr << "ARP reply received, all queued packets have been processed" << std::endl;
          return;
        }
      }
    }
    else {};
  }

  //deal with ip
  else if (ntohs(E_header.ether_type) == ethertype_ip){
    if ( packet.size() < (sizeof(E_header) + sizeof(IP_header)) ) {
      std::cerr << "Received packet, but the packet size is too small to contain a IP packet, ignoring" << std::endl;
      return;
    }
    memcpy(&IP_header, &(packet[sizeof(E_header)]), sizeof(IP_header));

    //checksum
    uint16_t temp_checksum = IP_header.ip_sum;
    IP_header.ip_sum = 0;
    IP_header.ip_sum = simple_router::cksum((const void *)&IP_header, sizeof(IP_header));;
    if (IP_header.ip_sum != temp_checksum){
      std::cerr << "check sum not correct, packet corrupted " << std::endl;
      return;
    }

    //handle ip_protocal = 1
    if (findIfaceByIp(IP_header.ip_dst) != nullptr){

      struct icmp_hdr ICMP_header;
      if (IP_header.ip_p == 1){//means ICMP
        if ( packet.size() < (sizeof(E_header) + sizeof(IP_header) +sizeof(ICMP_header))) {
          std::cerr << "Received packet, but the packet size is too small to contain a ICMP, ignoring" << std::endl;
          return;
        }
        memcpy(&ICMP_header, &(packet[sizeof(E_header) + sizeof(IP_header)]), sizeof(ICMP_header));
        //icmp checksum
        void* cksm_buffer = malloc(packet.size());
        memcpy(cksm_buffer, &(packet[sizeof(E_header) + sizeof(IP_header)]), packet.size()-(sizeof(E_header)+sizeof(IP_header)));
        uint16_t icmp_cksm =  ICMP_header.icmp_sum;
        ICMP_header.icmp_sum = 0;
        memcpy(cksm_buffer, &ICMP_header, sizeof(ICMP_header));
        ICMP_header.icmp_sum = simple_router::cksum((const void *)cksm_buffer, packet.size()-(sizeof(E_header)+sizeof(IP_header)) );//////marker!!
        free(cksm_buffer);
        if (icmp_cksm != ICMP_header.icmp_sum){
          std::cerr << "icmp checksum not correct, packet corrupted " << std::endl;
          return;
        }
        if (ICMP_header.icmp_type == 8){
          //if (findIfaceByIp(IP_header.ip_dst) == nullptr) std::cerr << "no findIfaceByIp(IP_header.ip_dst)!" << std::endl;

          //start findifbyip
            //std::cerr << "find in my ip "<< ipToString(findIfaceByIp(IP_header.ip_dst)->ip) << std::endl;
            Buffer echo_r(packet.size());
            memcpy(echo_r.data(), packet.data(), packet.size());
            memcpy(E_header.ether_dhost, E_header.ether_shost, sizeof(unsigned char)*ETHER_ADDR_LEN);
            memcpy(E_header.ether_shost, &(iface->addr[0]), sizeof(unsigned char)*ETHER_ADDR_LEN);
            memcpy(&(echo_r[0]), &E_header, sizeof(E_header));

            IP_header.ip_len = htons(packet.size()-sizeof(E_header));
            IP_header.ip_ttl = 64;
            IP_header.ip_p = 1;
            uint32_t temp_s = IP_header.ip_dst;
            IP_header.ip_dst = IP_header.ip_src;
            IP_header.ip_src = temp_s;
            IP_header.ip_sum = 0;
            IP_header.ip_sum = simple_router::cksum((const void *)&IP_header, sizeof(IP_header));
            memcpy(&(echo_r[sizeof(E_header)]), &IP_header, sizeof(IP_header));

            struct icmp_hdr echo_icmp;
            memcpy(&echo_icmp, &(packet[sizeof(E_header)+sizeof(IP_header)]), sizeof(echo_icmp));
            echo_icmp.icmp_type = 0;
            echo_icmp.icmp_code = 0;
            echo_icmp.icmp_sum = 0;
            memcpy(&echo_r[sizeof(E_header)+sizeof(IP_header)], &echo_icmp, sizeof(echo_icmp));
            echo_icmp.icmp_sum = simple_router::cksum((const void *)&echo_r[sizeof(E_header)+sizeof(IP_header)], packet.size()-(sizeof(E_header)+sizeof(IP_header)) );;
            memcpy(&echo_r[sizeof(E_header)+sizeof(IP_header)], &echo_icmp, sizeof(echo_icmp));
            sendPacket(echo_r, inIface);
            //print_hdrs(echo_r);
            std::cerr << "sending packet: icmp echo reply" << std::endl;
        }
      }
    
    }

    
    //forward
    else { 
      if (IP_header.ip_dst == iface->ip) return;

      //deal with ttl
      uint8_t time_to_live = IP_header.ip_ttl;
      if (time_to_live == 0){
        std::cerr << "time_to_live = 0, packet expired " << std::endl;
        return;
      }
      else {
        IP_header.ip_ttl -= 1;
        IP_header.ip_sum = 0;
        IP_header.ip_sum = simple_router::cksum((const void *)&IP_header, sizeof(IP_header));
      }
      struct RoutingTableEntry route_entry =getRoutingTable().lookup(IP_header.ip_dst);
      std::cerr << "next hop is" << std::endl;
      std::cerr << route_entry << std::endl;
      std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(IP_header.ip_dst);
      Buffer ret_packet(packet.size());
      memcpy(ret_packet.data(), packet.data(), packet.size());
      if (arp_entry == nullptr){
        std::cerr << "MAC address not found, queueing the packet" << std::endl;
        memcpy(&(ret_packet[sizeof(E_header)]), &IP_header, sizeof(IP_header));
        m_arp.queueRequest(IP_header.ip_dst, ret_packet, inIface);
      }
      else {
        std::cerr << "MAC address found" << std::endl;
        memcpy(E_header.ether_dhost, (arp_entry->mac).data(), sizeof(unsigned char)*ETHER_ADDR_LEN);
        memcpy(E_header.ether_shost, &(findIfaceByName(route_entry.ifName)->addr[0]), sizeof(unsigned char)*ETHER_ADDR_LEN);
        memcpy(&(ret_packet[0]), &E_header, sizeof(E_header));
        memcpy(&(ret_packet[sizeof(E_header)]), &IP_header, sizeof(IP_header));
        sendPacket(ret_packet, route_entry.ifName);
        std::cerr << "forwardede to next hop..." << std::endl;

      }
    
    
    }
    
  }


  return;



}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
