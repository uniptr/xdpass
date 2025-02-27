package fastpkt

// <linux/if_ether.h>
//
//	struct ethhdr {
//	    unsigned char h_dest[6];
//	    unsigned char h_source[6];
//	    __be16 h_proto;
//	};

type Ethernet struct {
	HwDest   [6]byte
	HwSource [6]byte
	HwProto  uint16
}

// <linux/if_vlan.h>
//
//	struct vlan_hdr {
//	    __be16 h_vlan_TCI;
//	    __be16 h_vlan_encapsulated_proto;
//	};

type VLAN struct {
	ID                uint16
	EncapsulatedProto uint16
}
