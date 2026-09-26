// dfg.sc — extract data-flow (reaching definitions) for all user methods.
// Invocation: joern --script dfg.sc --param file=/path/to/file.c

@main def exec(file: String): Unit = {

  def je(s: String): String = {
    val sb = new StringBuilder
    for (c <- Option(s).getOrElse("")) c match {
      case '"'  => sb ++= "\\\""
      case '\\' => sb ++= "\\\\"
      case '\n' => sb ++= "\\n"
      case '\r' => sb ++= "\\r"
      case '\t' => sb ++= "\\t"
      case c if c.toInt < 32 => sb ++= f"\\u${c.toInt}%04x"
      case c => sb += c
    }
    sb.toString
  }

  importCode.c(file)

  val targetName = new java.io.File(file).getName
  def isRealMethod(m: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean = {
    val src = Option(m.code).getOrElse("").trim
    !src.startsWith("#define")
  }
  def codeOf(node: Any): String = node match {
    case n: io.shiftleft.codepropertygraph.generated.nodes.Call              => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Identifier        => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Literal           => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Local             => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterOut=> Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Return            => Option(n.code).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Member            => Option(n.code).getOrElse("")
    case _ => ""
  }
  def nameOf(node: Any): String = node match {
    case n: io.shiftleft.codepropertygraph.generated.nodes.Call              => Option(n.name).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Identifier        => Option(n.name).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Local             => Option(n.name).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => Option(n.name).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterOut=> Option(n.name).getOrElse("")
    case n: io.shiftleft.codepropertygraph.generated.nodes.Member            => Option(n.name).getOrElse("")
    case _ => ""
  }
  def lineOf(node: Any): Int = node match {
    case n: io.shiftleft.codepropertygraph.generated.nodes.Call              => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.Identifier        => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.Literal           => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.Local             => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterOut=> n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.Return            => n.lineNumber.getOrElse(-1)
    case n: io.shiftleft.codepropertygraph.generated.nodes.Member            => n.lineNumber.getOrElse(-1)
    case _ => -1
  }

  val userMethods = cpg.method
    .filter(m => m.filename.endsWith(targetName))
    .filter(isRealMethod)
    .nameNot("<.*>")
    .l

  val methodsJson = userMethods.map { method =>
    val startLine = method.lineNumber.getOrElse(-1)
    val endLine   = method.lineNumberEnd.getOrElse(-1)
    val mName     = je(method.name)
    val sig       = je(method.signature)

    // reaching-def edges: node ← definitions that reach it
    val dfgEntries = method.cfgNode.l.flatMap { node =>
      node._reachingDefIn.l.map { defNode =>
        val line    = node.lineNumber.getOrElse(-1)
        val stmt    = je(Option(node.code).getOrElse("").trim.replaceAll("\\s+", " ").take(300))
        val varTok  = je(nameOf(defNode).trim)
        val useTok  = je(codeOf(defNode).trim.take(120))
        val defLine = lineOf(defNode)
        val defsJson = if (varTok.nonEmpty) s"""["$varTok"]""" else "[]"
        s"""{"line":$line,"stmt":"$stmt","var":"$varTok","use":"$useTok","def_line":$defLine,"defs":$defsJson}"""
      }
    }.distinct

    val dfgJson = dfgEntries.mkString("[", ",", "]")

    s"""{"name":"$mName","signature":"$sig","start_line":$startLine,"end_line":$endLine,"dfg":$dfgJson}"""
  }.mkString(",")

  println(s"""{"status":"ok","tool":"joern","classes":[{"name":"Global","methods":[$methodsJson]}]}""")
}
