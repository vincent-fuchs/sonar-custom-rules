package org.sonar.samples.java.checks;

import com.google.common.collect.ImmutableList;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.*;
import org.sonar.plugins.java.api.tree.Tree.Kind;

import java.util.List;
import java.util.stream.Collectors;


@Rule(key = "LogExceptionsCorrectlyRule")
public class LogExceptionsCorrectlyCheck extends IssuableSubscriptionVisitor {

    private static List<String> LOGGER_NAMES= ImmutableList.of("log","LOG","logger","LOGGER");

    @Override
    public List<Kind> nodesToVisit() {
        return ImmutableList.of(Kind.CATCH);
    }


    @Override
    public void visitNode(Tree tree) {

        CatchTree catchBlock = (CatchTree) tree;

        if(catchBlock.parameter().type().toString().equals("Exception")){

            String exceptionVariableName=catchBlock.parameter().simpleName().name();

            List<MethodInvocationTree> errorLogStatements = catchBlock.block().body().stream()
                .filter(statement -> isAlog(statement))
                .filter(statement -> isAnError(statement))
                .map(statement -> toMethodInvocationTree(statement))
                .collect(Collectors.toList());


            for(MethodInvocationTree errorLog : errorLogStatements){

                Arguments arguments=errorLog.arguments();

                boolean foundExceptionAsParam=arguments.stream().filter(arg -> arg.is(Kind.IDENTIFIER)).filter(arg -> arg.toString().equals(exceptionVariableName)).findAny().isPresent();

                if(!foundExceptionAsParam){
                    reportIssue(errorLog, "When logging an exception at error level, make sure you use a signature that preserves stacktrace");
                }

                System.out.println(arguments);

            }

        }
    }

    private MethodInvocationTree toMethodInvocationTree(StatementTree statement) {

        ExpressionStatementTree expression=(ExpressionStatementTree)statement;
        MethodInvocationTree methodCall=(MethodInvocationTree)expression.expression();
        return (MethodInvocationTree)methodCall.methodSelect().parent();
    }

    private boolean isAnError(StatementTree statement) {

        ExpressionStatementTree expression=(ExpressionStatementTree)statement;
        MethodInvocationTree methodCall=(MethodInvocationTree)expression.expression();
        MemberSelectExpressionTree memberSelectExpressionTree=(MemberSelectExpressionTree)methodCall.methodSelect();

        if(memberSelectExpressionTree.identifier().name().equals("error")){
            return true;
        }
        else{
            return false;
        }

    }

    private boolean isAlog(StatementTree statement) {

        if(statement.is(Kind.EXPRESSION_STATEMENT)){

            ExpressionStatementTree expression=(ExpressionStatementTree)statement;

            if(expression.expression().is(Kind.METHOD_INVOCATION)) {

                MethodInvocationTree methodCall=(MethodInvocationTree)expression.expression();

                if(methodCall.methodSelect().is(Kind.MEMBER_SELECT)){
                    MemberSelectExpressionTree memberSelectExpressionTree=(MemberSelectExpressionTree)methodCall.methodSelect();

                    if(memberSelectExpressionTree.expression().is(Kind.IDENTIFIER)){
                        IdentifierTree methodCallidentifier=(IdentifierTree)memberSelectExpressionTree.expression();

                        if(LOGGER_NAMES.contains(methodCallidentifier.name())){
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

}
