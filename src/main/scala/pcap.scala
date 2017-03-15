package example

import scala.scalanative._
import scala.scalanative.native.CString

@native.link("pcap")
@native.extern
object pcap {
  type pcap_pkthdr = native.CStruct4[native.CUnsignedInt,
                                     native.CUnsignedInt,
                                     native.CUnsignedInt,
                                     native.CUnsignedInt]

  def pcap_open_offline(fname: CString, errbuf: CString): native.Ptr[Unit] =
    native.extern

  def pcap_next(p: native.Ptr[Unit],
                h: native.Ptr[pcap_pkthdr]): native.CString = native.extern

  def pcap_close(p: native.Ptr[Unit]): Unit = native.extern

}
