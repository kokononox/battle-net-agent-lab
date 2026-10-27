// Reproduce the Windows SDK max macro without needing Windows headers.
#include <algorithm>
#include <cstdint>
#include <map>
#include <ostream>
#include <utility>
#define max(a,b) windows_max_macro(a,b)
#include "network_diagnostics.h"
#undef max
#include "phase_arm.h"
#include <cassert>
#include <sstream>
#include <string>
using namespace counter_diag;
Sample sample(Count total,Count tick,Count key=42,Count received=1,Count sent=1){Sample s;s.total=total;s.tick=tick;s.interfaces[key]={received,sent};return s;}
int main(){
 PhaseArm arm;assert(arm.arm(500000000,1000));assert(!arm.arm(900000000,2000));assert(arm.baseline==500000000&&arm.start==1000);
 Diagnostics d;d.observe(sample(100,1000));d.observe(sample(200,1250,42,2,2));
 assert(d.samples==2&&d.last_sample_gap_ms==250&&d.last_sample_delta_bytes==100);
 // A phase-time of zero does not imply a zero sample interval. No division/rate claim.
 d.observe(sample(107946607,1500,42,3,3),true);
 assert(d.phase_boundary_gap_ms==250&&d.phase_boundary_delta_bytes==107946407);
 assert(d.interface_set_changes==0&&!d.phase_boundary_interfaces_changed);
 d.observe(sample(107946608,2000,43,4,4));assert(d.interface_set_changes==1);
 Diagnostics replacement;replacement.observe(sample(100,0,42));replacement.observe(sample(200,250,43),true);
 assert(replacement.phase_boundary_interfaces_changed&&replacement.interface_set_changes==1);
 Diagnostics reset;reset.observe(sample(100,0,42,10,10));reset.observe(sample(200,250,42,1,20),true);
 assert(reset.counter_reset_intervals==1&&reset.phase_boundary_counter_reset);
 Diagnostics decrease;decrease.observe(sample(100,0));decrease.observe(sample(99,250),true);
 assert(decrease.counter_reset_intervals==1&&decrease.last_sample_delta_bytes==0);
 Diagnostics gap;gap.observe(sample(0,0));gap.observe(sample(1,10000),true);
 assert(gap.max_sample_gap_ms==10000&&gap.phase_boundary_gap_ms==10000);
 gap.observe(sample(2,10250),true);assert(gap.phase_boundary_gap_ms==10000);
 std::ostringstream out;d.json(out);assert(out.str().find("interfaces\"")==std::string::npos);
 assert(out.str().find("42")==std::string::npos); // private interface identity never serialized
 return 0;
}
