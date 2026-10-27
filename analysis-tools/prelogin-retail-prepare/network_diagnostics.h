#pragma once
#include <algorithm>
#include <cstdint>
#include <map>
#include <ostream>
#include <utility>

// Interface identifiers and absolute counters live in memory only; never output.
namespace counter_diag {
using Count = std::uint64_t;
struct Sample {
 Count total=0, tick=0;
 std::map<Count,std::pair<Count,Count>> interfaces;
};
struct Diagnostics {
 Count samples=0,interface_set_changes=0,counter_reset_intervals=0;
 Count last_sample_gap_ms=0,max_sample_gap_ms=0,last_sample_delta_bytes=0,max_sample_delta_bytes=0;
 bool phase_boundary_observed=false,phase_boundary_interfaces_changed=false,phase_boundary_counter_reset=false;
 Count phase_boundary_gap_ms=0,phase_boundary_delta_bytes=0;
 Sample previous;
 void observe(const Sample& now,bool boundary=false){
  if(samples){
   bool changed=now.interfaces.size()!=previous.interfaces.size(),reset=now.total<previous.total;
   for(const auto& item:previous.interfaces){
    const auto it=now.interfaces.find(item.first);
    if(it==now.interfaces.end()){changed=true;continue;}
    if(it->second.first<item.second.first||it->second.second<item.second.second)reset=true;
   }
   for(const auto& item:now.interfaces)if(previous.interfaces.find(item.first)==previous.interfaces.end())changed=true;
   last_sample_gap_ms=now.tick>=previous.tick?now.tick-previous.tick:0;
   last_sample_delta_bytes=now.total>=previous.total?now.total-previous.total:0;
   max_sample_gap_ms=(std::max)(max_sample_gap_ms,last_sample_gap_ms);
   max_sample_delta_bytes=(std::max)(max_sample_delta_bytes,last_sample_delta_bytes);
   if(changed)++interface_set_changes;
   if(reset)++counter_reset_intervals;
   if(boundary&&!phase_boundary_observed){
    phase_boundary_observed=true;phase_boundary_interfaces_changed=changed;phase_boundary_counter_reset=reset;
    phase_boundary_gap_ms=last_sample_gap_ms;phase_boundary_delta_bytes=last_sample_delta_bytes;
   }
  }
  ++samples;previous=now;
 }
 void json(std::ostream& o)const{
  o<<"{\"samples\":"<<samples<<",\"interface_set_changes\":"<<interface_set_changes
   <<",\"counter_reset_intervals\":"<<counter_reset_intervals<<",\"last_sample_gap_ms\":"<<last_sample_gap_ms
   <<",\"max_sample_gap_ms\":"<<max_sample_gap_ms<<",\"last_sample_delta_bytes\":"<<last_sample_delta_bytes
   <<",\"max_sample_delta_bytes\":"<<max_sample_delta_bytes<<",\"phase_boundary_observed\":"<<(phase_boundary_observed?"true":"false")
   <<",\"phase_boundary_gap_ms\":"<<phase_boundary_gap_ms<<",\"phase_boundary_delta_bytes\":"<<phase_boundary_delta_bytes
   <<",\"phase_boundary_interfaces_changed\":"<<(phase_boundary_interfaces_changed?"true":"false")
   <<",\"phase_boundary_counter_reset\":"<<(phase_boundary_counter_reset?"true":"false")<<"}";
 }
};
}
