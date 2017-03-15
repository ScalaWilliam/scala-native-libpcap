package com.scalawilliam.scalanative

import scala.scalanative.native
import scala.scalanative.native.CUnsignedInt

/**
  * We use this to avoid our own byte manipulation.
  * Ironically I have to do this with bytes in Java, so scala-native is already proving itself!
  */
@native.extern
object inet {

  def inet_ntoa(input: CUnsignedInt): native.CString = native.extern

}
