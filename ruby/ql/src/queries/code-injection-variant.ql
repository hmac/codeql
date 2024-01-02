import ruby
import codeql.ruby.DataFlow
import codeql.ruby.AST
import codeql.ruby.TaintTracking
import codeql.ruby.frameworks.data.internal.ApiGraphModels
import codeql.ruby.ApiGraphs
import codeql.ruby.frameworks.core.Kernel
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.frameworks.ActionController
private import codeql.ruby.CFG
import codeql.ruby.security.CodeInjectionCustomizations
private import codeql.ruby.dataflow.BarrierGuards
import codeql.ruby.ast.internal.Module
import codeql.ruby.dataflow.internal.DataFlowPrivate

private module Config implements DataFlow::StateConfigSig {
  class FlowState = CodeInjection::FlowState::State;

  predicate isSource(DataFlow::Node source, FlowState state) {
    state = source.(CodeInjection::Source).getAState()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    state = sink.(CodeInjection::Sink).getAState()
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CodeInjection::Sanitizer and
    not exists(node.(CodeInjection::Sanitizer).getAState())
    or
    node instanceof StringConstCompareBarrier
    or
    node instanceof StringConstArrayInclusionCallBarrier
  }

  predicate isBarrier(DataFlow::Node node, FlowState state) {
    node.(CodeInjection::Sanitizer).getAState() = state
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    isFlowFromViewInstanceVariable(node1, node2) or
    isFlowIntoViewMethod(node1, node2) or
    isFlowFromViewMethod(node1, node2)
  }
}

/**
 * Taint-tracking for detecting "Code injection" vulnerabilities.
 */
module CodeInjectionFlow = TaintTracking::GlobalWithState<Config>;

// from
//   CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink,
//   CodeInjection::Source sourceNode
// where
//   CodeInjectionFlow::flowPath(source, sink) and
//   sourceNode = source.getNode() and
//   // removing duplications of the same path, but different flow-labels.
//   sink =
//     min(CodeInjectionFlow::PathNode otherSink |
//       CodeInjectionFlow::flowPath(any(CodeInjectionFlow::PathNode s | s.getNode() = sourceNode),
//         otherSink) and
//       otherSink.getNode() = sink.getNode()
//     |
//       otherSink order by otherSink.getState().getStringRepresentation()
//     )
// select sink.getNode(), source, sink, "This code execution depends on a $@.", sourceNode,
//   "user-provided value"
from DataFlow::Node src, DataFlow::Node sink
where HmacTestFlow::flow(src, sink)
select src, sink

module HmacTestFlow = TaintTracking::Global<HmacTest>;

module HmacTest implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource and
    node.getLocation().getFile().getBaseName() = "repository_items_controller.rb" and
    node.getLocation().getStartLine() = 174
    or
    any()
  }

  predicate isSink(DataFlow::Node node) { any() }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    isFlowFromViewInstanceVariable(node1, node2) or
    isFlowIntoViewMethod(node1, node2) or
    isFlowFromViewMethod(node1, node2) or
    isFlowFromViewSelfToTemplate2(node1, node2)
  }
}

module Flow = DataFlow::Global<HmacTest>;

class ActionViewClass extends DataFlow::ClassNode {
  ActionViewClass() { this = DataFlow::getConstant("ApplicationComponent").getADescendentModule() }
}

Method getTemplateCallTarget(
  CfgNodes::ExprNodes::MethodCallCfgNode call, ErbFile template, ActionViewClass view
) {
  view = getTemplateAssociatedViewClass(template) and
  call.getLocation().getFile() = template and
  call.getReceiver().getExpr() instanceof SelfVariableAccess and
  result = lookupMethod(view, call.getMethodName())
}

predicate isFlowFromViewSelfToTemplate(DataFlow::Node node1, CfgNodes::ExprCfgNode e, string k) {
  node1.getLocation().getStartLine() = 7 and
  node1.getLocation().getFile() instanceof ErbFile and
  node1 = TExprNode(e) and
  k = e.getAPrimaryQlClass()
}

predicate h(CfgNodes::ExprNodes::SelfVariableAccessCfgNode n, DataFlow::Node m, DataFlow::Node p) {
  m = TExprNode(n) and HmacTestFlow::flow(p, m)
}

predicate isFlowFromViewSelfToTemplate2(DataFlow::Node node1, DataFlow::Node node2) {
  p(_, node1, _, node2)
}

predicate y(DataFlow::CallNode call, DataFlow::Node arg, ActionViewClass view, DataFlow::Node node2) {
  call.getMethodName() = "render" and
  call.getArgument(0) = arg and
  view.trackInstance().getAValueReachableFromSource() = arg and
  exists(ErbFile template |
    view = getTemplateAssociatedViewClass(template) and node2.getLocation().getFile() = template
  ) and
  none()
}

predicate u(DataFlow::Node n, int startCol, DataFlow::Node prev) {
  n.getLocation().getFile() instanceof ErbFile and
  n.getLocation().getStartLine() = 7 and
  startCol = n.getLocation().getStartColumn() and
  prev = n.getAPredecessor()
}

predicate p(
  DataFlow::CallNode call, DataFlow::Node arg, ActionViewClass view, SsaSelfDefinitionNode node2
) {
  call.getMethodName() = "render" and
  call.getArgument(0) = arg and
  view.trackInstance().getAValueReachableFromSource() = arg and
  exists(ErbFile template |
    view = getTemplateAssociatedViewClass(template) and node2.getLocation().getFile() = template
  ) and
  node2.getSelfScope() instanceof Toplevel
}

predicate r(SsaDefinitionExtNode node, SelfVariable var, VariableAccess a) {
  var = node.getVariable() and a = var.getDefiningAccess()
}

predicate isFlowFromViewInstanceVariable(DataFlow::Node node1, DataFlow::Node node2) {
  // instance variables in the view
  exists(string name, ErbFile template, ActionViewClass view |
    // match read to write on variable name
    getTemplateAssociatedViewClass(template) = view and
    exists(AssignExpr ae, FinalInstanceVarWrite write |
      ae.getParent+() = view.getAnInstanceMethod().asExpr().getExpr() and
      ae = write.getAnAssignExpr() and
      name = write.getVariable().getName() and
      node1.asExpr().getExpr() = ae.getRightOperand()
    ) and
    node2.getLocation().getFile() = template and
    node2.(DataFlow::VariableAccessNode).asVariableAccessAstNode().getVariable().getName() = name
    // propagate taint from assignment RHS expr to variable read access in view
  )
}

predicate isFlowIntoViewMethod(DataFlow::Node node1, DataFlow::Node node2) {
  // flow from template into ActionView method
  exists(
    ErbFile template, ActionViewClass view, DataFlow::MethodNode method, string name,
    DataFlow::CallNode call, int argIndex
  |
    method = view.getInstanceMethod(name) and
    view = getTemplateAssociatedViewClass(template) and
    call.getMethodName() = name and
    call.getLocation().getFile() = template and
    call.getArgument(argIndex) = node1 and
    method.getParameter(argIndex) = node2
  )
}

predicate isFlowFromViewMethod(DataFlow::Node node1, DataFlow::Node node2) {
  // flow out of ActionView method into template
  exists(ActionViewClass view, ErbFile template, DataFlow::MethodNode method, string name |
    method.getAReturnNode() = node1 and
    method = view.getInstanceMethod(name) and
    node2.(DataFlow::CallNode).getMethodName() = name and
    node2.getLocation().getFile() = template and
    view = getTemplateAssociatedViewClass(template)
  )
}

ActionViewClass getTemplateAssociatedViewClass(ErbFile template) {
  // template is in same directory as view
  exists(File viewFile | viewFile = result.getADeclaration().getFile() |
    template.getParentContainer().getAbsolutePath() =
      viewFile.getParentContainer().getAbsolutePath() and
    viewFile.getStem() + ".html" = template.getStem()
  )
}

/**
 * A `VariableWriteAccessCfgNode` that is not succeeded (locally) by another
 * write to that variable.
 */
private class FinalInstanceVarWrite extends CfgNodes::ExprNodes::InstanceVariableWriteAccessCfgNode {
  private InstanceVariable var;

  FinalInstanceVarWrite() {
    var = this.getExpr().getVariable() and
    not exists(CfgNodes::ExprNodes::InstanceVariableWriteAccessCfgNode succWrite |
      succWrite.getExpr().getVariable() = var
    |
      succWrite = this.getASuccessor+()
    )
  }

  InstanceVariable getVariable() { result = var }

  AssignExpr getAnAssignExpr() { result.getLeftOperand() = this.getExpr() }
}
