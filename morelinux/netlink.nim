## Accesses the Netlink sockets
# Public API
import options
export options

type
  NlLink* = object
    index*: int32
    attrs*: seq[RtAttr]

  RtAttr* = object
    kind*: uint16
    data*: string

include morelinux/netlinkimpl

proc parseLink(response: string): NlLink =
  let ifinfo = unpackStruct(response[0..^1], ifinfomsg)
  let rtAttrs = unpackRtAttrs(response[sizeof(ifinfomsg)..^1])
  return NlLink(index: ifinfo.index, attrs: rtAttrs)

proc findAttr(attrs: seq[RtAttr], kind: uint16): string =
  for attr in attrs:
    if attr.kind == kind:
      return attr.data

  return nil

proc findAttr(link: NlLink, kind: uint16): string =
  return link.attrs.findAttr(kind)

proc parseNested(data: string): seq[RtAttr] =
  return unpackRtAttrs(data)

proc asciizToString(s: string): string =
  if s == nil:
    return nil
  if s.len == 0 or s[^1] != '\0':
    raise newException(ValueError, "bad asciiz string")
  return s[0..^2]

proc alias*(link: NlLink): string =
  link.findAttr(IFLA_IFALIAS).asciizToString

proc name*(link: NlLink): string =
  link.findAttr(IFLA_IFNAME).asciizToString

proc kind*(link: NlLink): string =
  link.findAttr(IFLA_LINKINFO).parseNested().findAttr(IFLA_INFO_KIND).asciizToString

proc getLinks*(): seq[NlLink] =
  let msg = ifinfomsg()
  var data = makeMessage(RTM_GETLINK, bulk=true, body=packStruct(msg))
  let sock = sendMessage(NETLINK_ROUTE, data)
  defer: discard close(sock)

  result = @[]
  for response in readResponse(sock, bulk=true):
    result.add parseLink(response)

proc getLink*(name: string): Option[NlLink] =
  for link in getLinks():
    if link.name == name:
      return some(link)

  return none(NlLink)

when isMainModule:
  for link in getLinks():
    echo link.index, ": ", link.name, " (kind: ", link.kind, ")"
