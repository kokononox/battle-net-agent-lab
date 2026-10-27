#pragma once
#include <cstdint>
// An immutable baseline established BEFORE the worker receives permission to request.
struct PhaseArm {
 bool armed=false;std::uint64_t baseline=0,start=0;
 bool arm(std::uint64_t count,std::uint64_t tick){if(armed)return false;baseline=count;start=tick;armed=true;return true;}
};
