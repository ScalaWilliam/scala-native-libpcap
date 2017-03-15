package example

import scala.scalanative._
import scala.scalanative.native._

/**
  * Created by me on 15/03/2017.
  */
object HelloWorld {

  // wget https://github.com/fox-it/quantuminsert/raw/master/presentations/brocon2015/pcaps/id1.cn-inject.pcap
  def main(args: Array[String]): Unit = {

    /**
      * If we're reading from all interfaces on Linux we may be reading a "Linux Cooked Capture" file/stream
      * which has an extra 2 bytes to compensate for a missing frame header.
      *
      * @see https://wiki.wireshark.org/SLL
      */
    val readOffset = {
      val cooked = args.contains("cooked")
      if (cooked) 2 else 0
    }
    val live = args.contains("live")
    val errorBuffer = native.stackalloc[Byte](256)
    val pcapHandle = if (live) {
      pcap.pcap_open_live(
        deviceName = toCString("any"),
        snapLen = Short.MaxValue,
        promisc = 0,
        to_ms = 10,
        errbuf = errorBuffer
      )
    } else {
      pcap.pcap_open_offline(fname = toCString(args.last),
                             errbuf = errorBuffer)
    }
    if (pcapHandle == null) {
      println(s"Failed: ${fromCString(errorBuffer)}")
      sys.exit(1)
    }
    val packetHeaderPointer: native.Ptr[pcap.pcap_pkthdr] =
      native.stackalloc[pcap.pcap_pkthdr]
    var packetReadData = pcap.pcap_next(pcapHandle, packetHeaderPointer)
    var continue = true
    while (continue) {
      if (packetReadData != null) {
        val byte: Byte = !(packetReadData + 0)
        val seconds = !packetHeaderPointer._1
        val caplen = !packetHeaderPointer._3
        println(byte, caplen)
      } else if (!live) {
        continue = false
      }
      if (continue) {
        packetReadData = pcap.pcap_next(pcapHandle, packetHeaderPointer)
      }
    }

    pcap.pcap_close(pcapHandle)
  }
}
