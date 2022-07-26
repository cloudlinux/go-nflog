package nflog

import (
	"encoding/binary"
	"log"
	"time"

	"github.com/florianl/go-nflog/v2/internal/unix"

	"github.com/mdlayher/netlink"
)

func extractAttribute(a *Attribute, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case nfUlaAttrPacketHdr:
			a.HwProtocol = binary.BigEndian.Uint16(ad.Bytes()[:2])
			a.Hook = uint8(ad.Bytes()[3])
		case nfUlaAttrMark:
			ad.ByteOrder = binary.BigEndian
			a.Mark = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrTimestamp:
			sec := binary.BigEndian.Uint64(ad.Bytes()[:8])
			usec := binary.BigEndian.Uint64(ad.Bytes()[8:])
			a.Timestamp = time.Unix(int64(sec), int64(usec)*1000)
		case nfUlaAttrIfindexIndev:
			ad.ByteOrder = binary.BigEndian
			a.InDev = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrIfindexOutdev:
			ad.ByteOrder = binary.BigEndian
			a.OutDev = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrIfindexPhysIndev:
			ad.ByteOrder = binary.BigEndian
			a.PhysInDev = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrIfindexPhysOutdev:
			ad.ByteOrder = binary.BigEndian
			a.PhysOutDev = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrHwaddr:
			hwAddrLen := binary.BigEndian.Uint16(ad.Bytes()[:2])
			a.HwAddr = (ad.Bytes())[4 : 4+hwAddrLen]
		case nfUlaAttrPayload:
			a.Payload = ad.Bytes()
		case nfUlaAttrPrefix:
			a.Prefix = ad.String()
		case nfUlaAttrUID:
			ad.ByteOrder = binary.BigEndian
			a.UID = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrSeq:
			ad.ByteOrder = binary.BigEndian
			a.Seq = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrSeqGlobal:
			ad.ByteOrder = binary.BigEndian
			a.SeqGlobal = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrGID:
			ad.ByteOrder = binary.BigEndian
			a.GID = ad.Uint32()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrHwType:
			ad.ByteOrder = binary.BigEndian
			a.HwType = ad.Uint16()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrHwHeader:
			a.HwHeader = ad.Bytes()
		case nfUlaAttrHwLen:
			ad.ByteOrder = binary.BigEndian
			a.HwLen = ad.Uint16()
			ad.ByteOrder = nativeEndian
		case nfUlaAttrCt:
			a.Ct = ad.Bytes()
		case nfUlaAttrCtInfo:
			ad.ByteOrder = binary.BigEndian
			a.CtInfo = ad.Uint32()
			ad.ByteOrder = nativeEndian
		default:
			logger.Printf("Unknown attribute: %d %v\n", ad.Type(), ad.Bytes())
		}
	}

	return ad.Err()
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(logger *log.Logger, msg []byte) (Attribute, error) {
	attrs := Attribute{}

	offset := checkHeader(msg[:2])
	if err := extractAttribute(&attrs, logger, msg[offset:]); err != nil {
		return attrs, err
	}
	return attrs, nil
}
