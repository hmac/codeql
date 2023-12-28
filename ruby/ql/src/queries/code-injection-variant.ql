import ruby
import codeql.ruby.DataFlow
import codeql.ruby.AST
import codeql.ruby.TaintTracking
import codeql.ruby.dataflow.RemoteFlowSources
private import codeql.ruby.CFG
import codeql.ruby.security.CodeInjectionCustomizations
private import codeql.ruby.dataflow.BarrierGuards
import codeql.ruby.ast.internal.Module
import codeql.ruby.dataflow.internal.DataFlowPrivate

module CodeInjectionFlow = TaintTracking::GlobalWithState<Config>;

from
  CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink,
  CodeInjection::Source sourceNode
where
  CodeInjectionFlow::flowPath(source, sink) and
  sourceNode = source.getNode() and
  // removing duplications of the same path, but different flow-labels.
  sink =
    min(CodeInjectionFlow::PathNode otherSink |
      CodeInjectionFlow::flowPath(any(CodeInjectionFlow::PathNode s | s.getNode() = sourceNode),
        otherSink) and
      otherSink.getNode() = sink.getNode()
    |
      otherSink order by otherSink.getState().getStringRepresentation()
    )
select sink.getNode(), source, sink, "This code execution depends on a $@.", sourceNode,
  "user-provided value"

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
    isFlowFromViewSelfToTemplate(node1, node2)
  }
}

class ActionViewClass extends DataFlow::ClassNode {
  ActionViewClass() { this = DataFlow::getConstant("ApplicationComponent").getADescendentModule() }
}

predicate isFlowFromViewSelfToTemplate(DataFlow::Node node1, SsaDefinitionExtNode node2) {
  node1 instanceof DataFlow::SelfParameterNode and
  node2.getVariable() instanceof SelfVariable and
  exists(DataFlow::MethodNode method, ErbFile template, ActionViewClass view |
    getTemplateAssociatedViewClass(template) = view and
    node2.getLocation().getFile() = template and
    node1 = method.getSelfParameter() and
    method = view.getAnInstanceMethod()
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
