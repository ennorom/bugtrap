// member_types.sc — extract declared types for every `parent.member` /
// `parent->member` access in user methods of the target file.
//
// Output (stdout JSON, last object):
// {
//   "status": "ok", "tool": "joern", "mode": "member_types",
//   "accesses": [
//     {
//       "line": 4323,
//       "expr": "pmksa->bssid",
//       "op": "->",
//       "parent_expr": "pmksa",
//       "parent_type": "cfg80211_pmksa*",
//       "member": "bssid",
//       "member_type": "unsigned char*",
//       "is_pointer": true,
//       "is_inline_array": false,
//       "resolved": true
//     }, ...
//   ]
// }
//
// `resolved=false` means Joern could not pin a real type (typeFullName was
// ANY/<UNKNOWN>/empty) — likely because the relevant struct decl was not in
// the parsed source set. The decision agent should treat unresolved members
// conservatively (assume nullable pointer) rather than guessing inline-array.

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

  def jb(b: Boolean): String = if (b) "true" else "false"

  def unresolved(t: String): Boolean = {
    val s = Option(t).getOrElse("").trim
    s.isEmpty || s == "ANY" || s == "<UNKNOWN>" || s == "<empty>" || s == "<global>"
  }

  importCode.c(file)

  val targetName = new java.io.File(file).getName

  def fileMatches(call: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val names = call.file.name.l
    names.exists(n => Option(n).getOrElse("").endsWith(targetName))
  }

  val indirect = cpg.call.name("<operator>.indirectFieldAccess").l
  val direct   = cpg.call.name("<operator>.fieldAccess").l
  val accesses = (indirect ++ direct).filter(fileMatches)

  val rows = accesses.flatMap { call =>
    val line = call.lineNumber.map(_.toInt).getOrElse(-1)
    val expr = Option(call.code).getOrElse("").trim.take(200)
    val op   = if (call.name.contains("indirectFieldAccess")) "->" else "."
    val args = call.argument.l.sortBy(_.argumentIndex)
    val parentArg  = args.headOption
    val parentExpr = parentArg.map(a => Option(a.code).getOrElse("").trim.take(120)).getOrElse("")
    val parentTypeRaw = parentArg.map(a => Option(a.typeFullName).getOrElse("")).getOrElse("")
    val fieldArg  = args.lift(1)
    val fieldName = fieldArg.map(a => Option(a.code).getOrElse("").trim.take(80)).getOrElse("")
    val memberType = Option(call.typeFullName).getOrElse("")
    val mt = memberType.trim
    val isPointer = mt.endsWith("*") || mt.contains(" *") || mt.contains("*")
    val isInlineArray = mt.contains("[") && mt.contains("]")
    val resolved = !unresolved(mt)
    if (line < 0 || fieldName.isEmpty) None
    else Some(
      s"""{"line":$line,"expr":"${je(expr)}","op":"$op","parent_expr":"${je(parentExpr)}","parent_type":"${je(parentTypeRaw)}","member":"${je(fieldName)}","member_type":"${je(mt)}","is_pointer":${jb(isPointer)},"is_inline_array":${jb(isInlineArray)},"resolved":${jb(resolved)}}"""
    )
  }.distinct

  println(s"""{"status":"ok","tool":"joern","mode":"member_types","accesses":[${rows.mkString(",")}]}""")
}
