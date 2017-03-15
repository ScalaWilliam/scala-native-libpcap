package example

import scala.scalanative._
import scala.scalanative.native._

/**
  * Created by me on 15/03/2017.
  */
/**
  * If we're reading from all interfaces on Linux we may be reading a "Linux Cooked Capture" file/stream
  * which has an extra 2 bytes to compensate for a missing frame header.
  *
  * @see https://wiki.wireshark.org/SLL
  */
object HelloWorld {

  val SRC_IP_OFFSET: Int = 26
  val DST_IP_OFFSET: Int = SRC_IP_OFFSET + 4

  def process_packet(epochSecond: Long,
                     dataLength: Int,
                     data: CString,
                     cooked: Boolean): Unit = {
    val theOffset = if (cooked) 2 else 0
    val sourceIp = {
      val ip = !(data + SRC_IP_OFFSET + theOffset).cast[Ptr[CUnsignedInt]]
      fromCString(inet.inet_ntoa(ip))
    }
    val destIp = {
      val ip = !(data + DST_IP_OFFSET + theOffset).cast[Ptr[CUnsignedInt]]
      fromCString(inet.inet_ntoa(ip))
    }
    println(s"Time: $epochSecond, $sourceIp --> $destIp, ${dataLength} bytes")
  }

  def main(args: Array[String]): Unit = {
    val cooked = args.contains("cooked")
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
      println(s"Failed to open reader: ${fromCString(errorBuffer)}")
      sys.exit(1)
    }
    val packetHeaderPointer: native.Ptr[pcap.pcap_pkthdr] =
      native.stackalloc[pcap.pcap_pkthdr]
    var packetReadData = pcap.pcap_next(pcapHandle, packetHeaderPointer)
    var continue = true
    while (continue) {
      if (packetReadData != null) {
        process_packet(
          epochSecond = (!packetHeaderPointer._1).toLong,
          dataLength = (!packetHeaderPointer._3).toInt,
          data = packetReadData,
          cooked = cooked
        )
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
