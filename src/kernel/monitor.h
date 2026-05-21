// SPDX-License-Identifier: GPL-2.0
#ifndef __MONITOR_H
#define __MONITOR_H

struct four_tuple { // Estrutura da 4-tuple
	__u32 saddr; // Endereço ipv4 em ntwork byte order como é armazenado no kernel
	__u32 daddr; // Endereço ipv4 em ntwork byte order como é armazenado no kernel
	__u16 sport; // Portas em host byte order que são convertidos pelo tracepoint
	__u16 dport; // Portas em host byte order que são convertidos pelo tracepoint
};

#endif
