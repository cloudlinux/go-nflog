package nflog

import (
	"bytes"
	"encoding/binary"
	"log"
	"time"

	"github.com/florianl/go-nflog/v2/internal/unix"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

const (
	sizeOfUint16 = 2
	sizeOfUint32 = 4
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
			var sec, usec int64
			r := bytes.NewReader(ad.Bytes()[:8])
			if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
				return err
			}
			r = bytes.NewReader(ad.Bytes()[8:])
			if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
				return err
			}
			a.Timestamp = time.Unix(sec, usec*1000)
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

func unmarshalAttribute(a *Attribute, logger *log.Logger, data []byte) error {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		logger.Printf("Unmarshal attributes failed: %v\n", err)
	}

	for _, attr := range attrs {
		switch attr.Type & attrTypeMask {
		case nfUlaAttrPacketHdr:
			if len(attr.Data) >= sizeOfUint16+1 {
				a.HwProtocol = binary.BigEndian.Uint16(attr.Data[:2])
				a.Hook = uint8(attr.Data[3])
			}
		case nfUlaAttrMark:
			if len(attr.Data) >= sizeOfUint32 {
				a.Mark = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrTimestamp:
			var sec, usec int64
			r := bytes.NewReader(attr.Data[:8])
			if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
				return err
			}
			r = bytes.NewReader(attr.Data[8:])
			if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
				return err
			}
			a.Timestamp = time.Unix(sec, usec*1000)
		case nfUlaAttrIfindexIndev:
			if len(attr.Data) >= sizeOfUint32 {
				a.InDev = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrIfindexOutdev:
			if len(attr.Data) >= sizeOfUint32 {
				a.OutDev = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrIfindexPhysIndev:
			if len(attr.Data) >= sizeOfUint32 {
				a.PhysInDev = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrIfindexPhysOutdev:
			if len(attr.Data) >= sizeOfUint32 {
				a.PhysOutDev = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrHwaddr:
			if len(attr.Data) >= sizeOfUint32 {
				hwAddrLen := binary.BigEndian.Uint16(attr.Data[:2])
				if len(attr.Data[4:]) >= int(hwAddrLen) {
					a.HwAddr = attr.Data[4 : 4+hwAddrLen]
				}
			}
		case nfUlaAttrPayload:
			a.Payload = attr.Data
		case nfUlaAttrPrefix:
			a.Prefix = nlenc.String(attr.Data)
		case nfUlaAttrUID:
			if len(attr.Data) >= sizeOfUint32 {
				a.UID = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrSeq:
			if len(attr.Data) >= sizeOfUint32 {
				a.Seq = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrSeqGlobal:
			if len(attr.Data) >= sizeOfUint32 {
				a.SeqGlobal = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrGID:
			if len(attr.Data) >= sizeOfUint32 {
				a.GID = binary.BigEndian.Uint32(attr.Data[:4])
			}
		case nfUlaAttrHwType:
			if len(attr.Data) >= sizeOfUint16 {
				a.HwType = binary.BigEndian.Uint16(attr.Data[:2])
			}
		case nfUlaAttrHwHeader:
			a.HwHeader = attr.Data
		case nfUlaAttrHwLen:
			if len(attr.Data) >= sizeOfUint16 {
				a.HwLen = binary.BigEndian.Uint16(attr.Data[:2])
			}
		case nfUlaAttrCt:
			a.Ct = attr.Data
		case nfUlaAttrCtInfo:
			if len(attr.Data) >= sizeOfUint32 {
				a.CtInfo = binary.BigEndian.Uint32(attr.Data[:4])
			}
		default:
			logger.Printf("Unknown attribute: %d\n", attr.Type)
		}
	}

	return nil
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
	if err := unmarshalAttribute(&attrs, logger, msg[offset:]); err != nil {
		return attrs, err
	}
	return attrs, nil
}
