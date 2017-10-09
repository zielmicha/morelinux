import morelinux/netlinkimpl, morelinux/netlink, os, posix, collections/bytes, endians

const
  AF_NETLINK = 16

const
  NFNL_SUBSYS_NONE = 0
  NFNL_SUBSYS_CTNETLINK = 1
  NFNL_SUBSYS_CTNETLINK_EXP = 2
  NFNL_SUBSYS_QUEUE = 3
  NFNL_SUBSYS_ULOG = 4
  NFNL_SUBSYS_OSF = 5
  NFNL_SUBSYS_IPSET = 6
  NFNL_SUBSYS_ACCT = 7
  NFNL_SUBSYS_CTNETLINK_TIMEOUT = 8
  NFNL_SUBSYS_CTHELPER = 9
  NFNL_SUBSYS_NFTABLES = 10
  NFNL_SUBSYS_NFT_COMPAT = 11
  NFNL_SUBSYS_COUNT = 12

const
  NFULNL_CFG_CMD_NONE = 0
  NFULNL_CFG_CMD_BIND = 1
  NFULNL_CFG_CMD_UNBIND = 2
  NFULNL_CFG_CMD_PF_BIND = 3
  NFULNL_CFG_CMD_PF_UNBIND = 4

const
  NFULNL_MSG_PACKET = 0
  NFULNL_MSG_CONFIG = 1

const
  NFULA_UNSPEC = 0
  NFULA_PACKET_HDR = 1
  NFULA_MARK = 2
  NFULA_TIMESTAMP = 3
  NFULA_IFINDEX_INDEV = 4
  NFULA_IFINDEX_OUTDEV = 5
  NFULA_IFINDEX_PHYSINDEV = 6
  NFULA_IFINDEX_PHYSOUTDEV = 7
  NFULA_HWADDR = 8
  NFULA_PAYLOAD = 9
  NFULA_PREFIX = 10
  NFULA_UID = 11
  NFULA_SEQ = 12
  NFULA_SEQ_GLOBAL = 13
  NFULA_GID = 14
  NFULA_HWTYPE = 15
  NFULA_HWHEADER = 16
  NFULA_HWLEN = 17
  NFULA_CT = 18
  NFULA_CT_INFO = 19

const
  NFULA_CFG_CMD = 1

type
  nfgenmsg = object
    family: uint8
    version: uint8
    resid: uint16

  nfattr = object
    len: uint16
    kind: uint16

  nflogheader = object
    family: uint8
    version: uint8
    resId: uint16

proc htons(a: uint16): uint16 =
  return cast[uint16](htons(cast[int16](a)))

proc configMsg(sock: SocketHandle, body: string) =
  sock.sendMessage(makeMessage((NFNL_SUBSYS_ULOG shl 8) or NFULNL_MSG_CONFIG, body=body, bulk=false))

proc configMsg(sock: SocketHandle, cmd: uint8, resId: uint16=0) =
  configMsg(sock,
            packStruct(nfgenmsg(family: uint8(AF_INET), version: 0, resId: htons(resId))) &
            packStruct(nfattr(len: 5, kind: NFULA_CFG_CMD)) &
            packStruct(cmd))


proc createCaptureSocket*(): SocketHandle =
  let sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
  doAssert(sock.cint > 0)

  sock.configMsg(NFULNL_CFG_CMD_PF_BIND, 0)
  discard sock.readResponse(bulk=false, ignoreError=true)

  sock.configMsg(NFULNL_CFG_CMD_BIND, 0)
  discard sock.readResponse(bulk=false, ignoreError=true)

  return sock

proc readPackets*(sock: SocketHandle, expectedPrefix: string): seq[string] =
  result = @[]
  for pkt in sock.readResponse(bulk=false):
    let header = unpackStruct(pkt[0..<4], nflogheader)
    let attrs = unpackRtAttrs(pkt[4..^1])
    let prefix = findAttr(attrs, uint16(NFULA_PREFIX)).asciizToString
    if prefix == expectedPrefix:
      result.add findAttr(attrs, uint16(NFULA_PAYLOAD))
