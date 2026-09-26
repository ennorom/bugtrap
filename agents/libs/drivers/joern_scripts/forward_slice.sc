// forward_slice.sc — intra-procedural forward slice for C/C++/Java.
// Invocation:
//   joern --script forward_slice.sc --param file=/abs/path/to/source --param lines=42,57 [--param var=identifier] [--param widen=5]
//
// `lines` is a comma-separated list of seed line numbers. All seeds are
// walked forward in one PDG traversal and the union is returned.
//
// `widen` (default 0) is an opt-in fallback radius: when *exact* line seeding
// yields zero CFG nodes, the script widens the seed search to CFG nodes
// within ±widen lines of any requested seed, constrained to the SAME user
// method that brackets the requested line. The widening NEVER fires when
// exact seeding already finds nodes, so output for previously-successful
// slices is bitwise unchanged when widen>0 is passed. When the widen
// fallback fires, the actual lines used are reported in the criterion as
// `widened_from`/`widened_to`/`widen_radius` for transparency.
//
// Output (single-line JSON):
//   {"status":"ok","tool":"joern","criterion":{"lines":[N,...],"var":"..."},
//    "slice_lines":[...],"slice_stmts":[{"line":N,"stmt":"..."}, ...],
//    "slice_code":"...","seed_count":K}

import io.shiftleft.codepropertygraph.generated.nodes._
import io.shiftleft.semanticcpg.language._
import scala.collection.mutable

@main def exec(file: String, lines: String, `var`: String = "", widen: String = "0"): Unit = {

  def je(s: String): String = {
    val sb = new StringBuilder
    for (c <- Option(s).getOrElse("")) c match {
      case '"'  => sb ++= "\\\""
      case '\\' => sb ++= "\\\\"
      case '\n' => sb ++= "\\n"
      case '\r' => sb ++= "\\r"
      case '\t' => sb ++= "\\t"
      case ch if ch.toInt < 32 => sb ++= f"\\u${ch.toInt}%04x"
      case ch => sb += ch
    }
    sb.toString
  }

  val varName = `var`
  val widenRadius: Int =
    try math.max(0, widen.trim.toInt) catch { case _: Throwable => 0 }
  val seedLines: Set[Int] =
    lines.split(",").iterator.map(_.trim).filter(_.nonEmpty).flatMap { s =>
      try Some(s.toInt) catch { case _: Throwable => None }
    }.toSet

  importCode(file)

  val userMethods = cpg.method
    .nameNot("<.*>")
    .filter(m => m.lineNumber.isDefined && m.lineNumberEnd.isDefined)
    .l

  val nodesAtLines: List[CfgNode] = userMethods.flatMap { m =>
    m.ast.isCfgNode.filter(n => n.lineNumber.exists(ln => seedLines.contains(ln))).l
  }

  // Opt-in widen fallback: ONLY fires when exact seeding found zero nodes AND
  // widenRadius > 0. Bounded to the user method that brackets each requested
  // seed line so unrelated code elsewhere in the file is never pulled in.
  var widenedSeedLines: Set[Int] = Set.empty
  val seedsRaw: List[CfgNode] =
    if (nodesAtLines.nonEmpty || widenRadius <= 0 || seedLines.isEmpty) nodesAtLines
    else {
      val collected = mutable.LinkedHashSet[CfgNode]()
      seedLines.foreach { seed =>
        val containing = userMethods.filter { m =>
          val s = m.lineNumber.get
          val e = m.lineNumberEnd.get
          seed >= s && seed <= e
        }
        val scope = if (containing.nonEmpty) containing else userMethods
        scope.foreach { m =>
          val s = m.lineNumber.get
          val e = m.lineNumberEnd.get
          val lo = math.max(s, seed - widenRadius)
          val hi = math.min(e, seed + widenRadius)
          m.ast.isCfgNode.foreach { n =>
            n.lineNumber.foreach { ln =>
              if (ln >= lo && ln <= hi) {
                collected += n
                widenedSeedLines += ln
              }
            }
          }
        }
      }
      collected.toList
    }

  val matching: List[CfgNode] =
    if (varName.nonEmpty)
      seedsRaw.filter(n => Option(n.code).getOrElse("").contains(varName))
    else seedsRaw

  val seeds: List[CfgNode] = if (matching.nonEmpty) matching else seedsRaw

  val visited = mutable.Set[Long]()
  val queue   = mutable.Queue[CfgNode]()
  seeds.foreach { s =>
    if (!visited.contains(s.id)) { visited += s.id; queue.enqueue(s) }
  }
  while (queue.nonEmpty) {
    val n = queue.dequeue()
    val succs: List[StoredNode] = n._reachingDefOut.l ++ n._cdgOut.l
    succs.foreach {
      case c: CfgNode =>
        if (!visited.contains(c.id)) { visited += c.id; queue.enqueue(c) }
      case _ => ()
    }
  }

  val sliceLines: Seq[Int] = visited.toList.flatMap { id =>
    cpg.graph.node(id) match {
      case n: CfgNode => n.lineNumber.toList
      case _          => Nil
    }
  }.distinct.sorted

  val fileLines: IndexedSeq[String] =
    try scala.io.Source.fromFile(file, "utf-8").getLines().toIndexedSeq
    catch { case _: Throwable => IndexedSeq.empty }

  def lineText(l: Int): String =
    if (l >= 1 && l <= fileLines.size) fileLines(l - 1) else ""

  val sliceStmts = sliceLines.map { l =>
    s"""{"line":$l,"stmt":"${je(lineText(l).trim.replaceAll("\\s+", " ").take(400))}"}"""
  }
  val sliceCode = je(sliceLines.map(l => f"$l%5d: ${lineText(l)}").mkString("\n"))

  val criterionLines = seedLines.toList.sorted.mkString(",")
  val widenSuffix: String =
    if (widenedSeedLines.nonEmpty)
      s""","widened_from":[$criterionLines],"widened_to":[${widenedSeedLines.toList.sorted.mkString(",")}],"widen_radius":$widenRadius"""
    else ""

  println(
    s"""{"status":"ok","tool":"joern","criterion":{"lines":[$criterionLines],"var":"${je(varName)}"$widenSuffix},""" +
    s""""slice_lines":[${sliceLines.mkString(",")}],""" +
    s""""slice_stmts":[${sliceStmts.mkString(",")}],""" +
    s""""slice_code":"$sliceCode","seed_count":${seeds.length}}"""
  )
}
