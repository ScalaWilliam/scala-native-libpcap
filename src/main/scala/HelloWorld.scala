package example

import scala.scalanative._
import scala.scalanative.native._

/**
  * Created by me on 15/03/2017.
  */
object HelloWorld {
  // wget https://github.com/fox-it/quantuminsert/raw/master/presentations/brocon2015/pcaps/id1.cn-inject.pcap
  val sourceFile = "/id1.cn-inject.pcap"

  def main(args: Array[String]): Unit = {
    val buffer = native.stackalloc[Byte](256)

    val r = pcap.pcap_open_offline(toCString(sourceFile), buffer)
    val q: native.Ptr[pcap.pcap_pkthdr] = native.stackalloc[pcap.pcap_pkthdr]
    var c: Int = 1
    var data = pcap.pcap_next(r, q)
    while (data != null) {
      val str = fromCString(data)
      val seconds = !q._1
      val micros = !q._2
      val caplen = !q._3
      val len = !q._4
      println(seconds, micros, caplen, len, str.length)
      data = pcap.pcap_next(r, q)
    }

    pcap.pcap_close(r)
  }
}
