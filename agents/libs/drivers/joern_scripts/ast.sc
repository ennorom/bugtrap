// ast.sc — extract AST node list for all user methods.
// Invocation: joern --script ast.sc --param file=/path/to/file.c

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

    val stmts = method.ast.l
      .filter(n => n.lineNumber.isDefined)
      .sortBy(_.lineNumber.getOrElse(0))
      .map { node =>
        val line     = node.lineNumber.getOrElse(-1)
        val stmt     = je(node.code.trim.replaceAll("\\s+", " ").take(300))
        val nodeType = je(node.label)
        s"""{"line":$line,"stmt":"$stmt","node_type":"$nodeType"}"""
      }
      .distinct

    val bodyJson = stmts.mkString("[", ",", "]")

    s"""{"name":"$mName","signature":"$sig","start_line":$startLine,"end_line":$endLine,"body":$bodyJson}"""
  }.mkString(",")

  println(s"""{"status":"ok","tool":"joern","classes":[{"name":"Global","methods":[$methodsJson]}]}""")
}
