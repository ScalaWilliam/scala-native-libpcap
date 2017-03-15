package com.scalawilliam.scalanative

import scala.scalanative.native
import scala.scalanative.native.{CInt, CString}

/**
  * @see https://linux.die.net/man/3/pcap
  */
@native.link("pcap")
@native.extern
object pcap {

  /** This is just a pointer for us, we don't care what is inside **/
  type pcap_handle = native.Ptr[Unit]

  type pcap_pkthdr = native.CStruct4[native.CUnsignedLong,
                                     native.CUnsignedLong,
                                     native.CUnsignedInt,
                                     native.CUnsignedInt]

  def pcap_open_live(deviceName: CString,
                     snapLen: CInt,
                     promisc: CInt,
                     to_ms: CInt,
                     errbuf: CString): pcap_handle =
    native.extern

  def pcap_open_offline(fname: CString, errbuf: CString): pcap_handle =
    native.extern

  def pcap_next(p: native.Ptr[Unit],
                h: native.Ptr[pcap_pkthdr]): native.CString = native.extern

  def pcap_close(p: native.Ptr[Unit]): Unit = native.extern

}
