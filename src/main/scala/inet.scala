package example

import scala.scalanative._
import scala.scalanative.native.CUnsignedInt

@native.extern
object inet {

  def inet_ntoa(input: CUnsignedInt): native.CString = native.extern

}
