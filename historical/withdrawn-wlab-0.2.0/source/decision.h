#ifndef WLAB_DECISION_H
#define WLAB_DECISION_H
#include <string.h>
#define APPROVED_SHA "1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a"
static int approved_hash(const char *s){return s && strcmp(s,APPROVED_SHA)==0;}
static int attach_passed(int consent,int identity,int launched,int exited,int exit_zero,int marker,int alive,int forced){
 return consent && identity && launched && exited && exit_zero && marker && alive && !forced;
}
#endif
