#ifndef LINUX_TYPES_H
#define LINUX_TYPE_H
// fuck all this include shit, we know what they are.
typedef unsigned char u8;
typedef unsigned char uint8_t;
typedef unsigned short u16;
typedef unsigned short uint16_t;
typedef unsigned long u32;
//typedef unsigned long uint32_t;
typedef unsigned long long ulong;
typedef unsigned long long u64;
typedef unsigned long long __u64;
typedef unsigned long long uint64_t;

typedef char s8;
typedef short s16;
typedef long s32;
typedef long long s64;

typedef int bool;

// oh, give it a fucking rest, will you? -- jmk
// Whenever I see code that asks what the native byte order is, it's almost certain the code is either wrong or misguided.  -- rob
// learn to fucking program -- me
typedef u16 __le16;
typedef u32 __le32;
typedef u64 __le64;

#define __packed	__attribute__((packed))
#define __aligned(x)		__attribute__((aligned(x)))
#define aligned_u64 __u64 __aligned(8)
#define CONFIG_IS_ENABLED(x) 0

typedef unsigned long long loff_t;
#endif 
