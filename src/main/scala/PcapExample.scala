// seems I can't use package directories with scala native just yet
package com.scalawilliam.scalanative

import scala.scalanative.native
import scala.scalanative.native._

/**
  * This example app reads online and offline via libpcap.
  * We're assuming it's installed on your system.
  * Basic usages:
  * <app> live
  * <app> live cooked
  * <app> <pcap file>
  * <app> cooked <pcap file>
  *
  * "Cooked": "Linux Cooked Capture" happens when we read from all interfaces on a Linux box.
  * These frames have an extra 2 bytes in front of them. For more, see: https://wiki.wireshark.org/SLL
  */
object PcapExample {

  val IpVersionByteOffset: Int = 14
  val PcapSourceIpv4AddressOffset: Int = 26
  val PcapDestinationIpv4AddressOffset: Int = PcapSourceIpv4AddressOffset + 4

  /**
    * We have a separate processing function to separate out the plumbing.
    *
    * @param data remember this is a pointer! But note that it may contain byte 0x00
    *             which is typically a string termination character - so we must pass dataLength explicitly.
    */
  def process_packet(epochSecond: Long,
                     dataLength: Int,
                     data: CString,
                     cooked: Boolean): Unit = {

    val offsetBytes = if (cooked) 2 else 0

    val hasEnoughData = dataLength > (offsetBytes + PcapDestinationIpv4AddressOffset + 4)
    if (!hasEnoughData) return

    /** IP version is stored in the first nibble of the target byte **/
    val isIpv4 = (!(data + IpVersionByteOffset + offsetBytes) >> 4) == 4
    if (!isIpv4) return

    /**
      * We move pointer a few bytes, then extract an Unsigned Int which
      * then we pass into the IP address call. It's quite verbose for
      * the time being because it's only a POC.
      ***/
    val sourceIp = {
      val ip = !(data + PcapSourceIpv4AddressOffset + offsetBytes)
        .cast[Ptr[CUnsignedInt]]
      fromCString(inet.inet_ntoa(ip))
    }
    val destIp = {
      val ip = !(data + PcapDestinationIpv4AddressOffset + offsetBytes)
        .cast[Ptr[CUnsignedInt]]
      fromCString(inet.inet_ntoa(ip))
    }
    print(s"Time: $epochSecond, $sourceIp --> $destIp, $dataLength bytes: [")
    (0 to Math.min(dataLength, 12))
      .map { n =>
        !(data + offsetBytes + n)
      }
      .foreach { v =>
        native.stdio.printf(c"%02X", v)
      }
    println("...]")
  }

  def main(args: Array[String]): Unit = Zone { zone => run(args)(zone) }

  def run(args: Array[String])(implicit zone:Zone): Unit = {
    val cooked = args.contains("cooked")
    val live = !cooked
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
