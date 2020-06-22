package org.sonar.samples.java.checks;

import static org.sonar.java.model.ExpressionUtils.skipParentheses;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.check.RuleProperty;

import org.sonar.java.checks.helpers.ExpressionsHelper;
import org.sonar.plugins.java.api.JavaFileScanner;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.*;
import org.sonar.plugins.java.api.tree.Tree.Kind;

import java.util.List;


@Rule(
    key = "LogExceptionsCorrectlyRule",
    name = "Logging correctly an exception requires to pass the exception as a parameter",
    description = "By not passing the exception as a parameter, it's very likely that we'll lose some important information when it gets logged",
    priority = Priority.BLOCKER,
    tags = {"error-handling"})
/**
 * Copy/pasted adapted from https://github.com/SonarSource/sonar-java/blob/aab82b68d764bccafea74dff6f334c22b77a1fff/java-checks/src/main/java/org/sonar/java/checks/CatchUsesExceptionWithContextCheck.java
 */
public class LogExceptionsCorrectlyCheck extends BaseTreeVisitor implements JavaFileScanner {

    private static final MethodMatchers GET_MESSAGE_METHODS = MethodMatchers.create()
        .ofSubTypes("java.lang.Throwable")
        .names("getMessage", "getLocalizedMessage")
        .addWithoutParametersMatcher()
        .build();

    private static final String JAVA_UTIL_LOGGING_LOGGER = "java.util.logging.Logger";
    private static final String SLF4J_LOGGER = "org.slf4j.Logger";

    private static final MethodMatchers JAVA_UTIL_LOG_METHOD = MethodMatchers.create()
        .ofTypes(JAVA_UTIL_LOGGING_LOGGER).names("log").withAnyParameters().build();

    private static final MethodMatchers JAVA_UTIL_LOGP_METHOD = MethodMatchers.create()
        .ofTypes(JAVA_UTIL_LOGGING_LOGGER).names("logp").withAnyParameters().build();

    private static final MethodMatchers JAVA_UTIL_LOGRB_METHOD = MethodMatchers.create()
        .ofTypes(JAVA_UTIL_LOGGING_LOGGER).names("logrb").withAnyParameters().build();

    private static final MethodMatchers LOGGING_METHODS = MethodMatchers.or(
        MethodMatchers.create()
            .ofTypes(JAVA_UTIL_LOGGING_LOGGER).names("config", "fine", "finer", "finest", "info", "severe", "warning").withAnyParameters().build(),
        JAVA_UTIL_LOG_METHOD,
        JAVA_UTIL_LOGP_METHOD,
        JAVA_UTIL_LOGRB_METHOD,
        MethodMatchers.create()
            .ofTypes(SLF4J_LOGGER).names("debug", "error", "info", "trace", "warn").withAnyParameters().build());

    private static final String EXCLUDED_EXCEPTION_TYPE = "java.lang.InterruptedException, " +
        "java.lang.NumberFormatException, " +
        "java.lang.NoSuchMethodException, " +
        "java.text.ParseException, " +
        "java.net.MalformedURLException, " +
        "java.time.format.DateTimeParseException";

    @RuleProperty(
        key = "exceptions",
        description = "List of exceptions which should not be checked. Use a simple dash ('-') character to check all exceptions.",
        defaultValue = "" + EXCLUDED_EXCEPTION_TYPE)
    public String exceptionsCommaSeparated = EXCLUDED_EXCEPTION_TYPE;

    private JavaFileScannerContext context;
    private Deque<LogExceptionsCorrectlyCheck.UsageStatus> usageStatusStack;
    private List<String> exceptions;
    private List<String> exceptionIdentifiers;
    private Set<CatchTree> excludedCatchTrees = new HashSet<>();

    @Override
    public void scanFile(JavaFileScannerContext context) {
        this.context = context;
        usageStatusStack = new ArrayDeque<>();
        if (context.getSemanticModel() != null) {
            scan(context.getTree());
        }
        excludedCatchTrees.clear();
    }

    @Override
    public void visitTryStatement(TryStatementTree tree) {
        if (containsEnumValueOf(tree.block())) {
            tree.catches().stream()
                .filter(c -> c.parameter().symbol().type().is("java.lang.IllegalArgumentException"))
                .findAny()
                .ifPresent(excludedCatchTrees::add);
        }
        super.visitTryStatement(tree);
    }

    private static boolean containsEnumValueOf(Tree tree) {
        LogExceptionsCorrectlyCheck.EnumValueOfVisitor visitor = new LogExceptionsCorrectlyCheck.EnumValueOfVisitor();
        tree.accept(visitor);
        return visitor.hasEnumValueOf;
    }

    private static class EnumValueOfVisitor extends BaseTreeVisitor {

        private static final MethodMatchers ENUM_VALUE_OF = MethodMatchers.create()
            .ofSubTypes("java.lang.Enum")
            .names("valueOf")
            .withAnyParameters()
            .build();

        private boolean hasEnumValueOf = false;

        @Override
        public void visitMethodInvocation(MethodInvocationTree tree) {
            if (ENUM_VALUE_OF.matches(tree)) {
                hasEnumValueOf = true;
            }
            super.visitMethodInvocation(tree);
        }

        @Override
        public void visitClass(ClassTree tree) {
            // skip anonymous classes
        }

        @Override
        public void visitLambdaExpression(LambdaExpressionTree lambdaExpressionTree) {
            // skip lambdas
        }
    }

    @Override
    public void visitCatch(CatchTree tree) {
        if (!isExcludedType(tree.parameter().type()) && !excludedCatchTrees.contains(tree)) {
            Symbol exception = tree.parameter().symbol();
            usageStatusStack.addFirst(new LogExceptionsCorrectlyCheck.UsageStatus(exception.usages()));
            super.visitCatch(tree);
            if (usageStatusStack.pop().isInvalid()) {
                context.reportIssue(this, tree.parameter(), "Either log or rethrow this exception.");
            }
        }
    }

    @Override
    public void visitMethodInvocation(MethodInvocationTree mit) {
        super.visitMethodInvocation(mit);
        if (LOGGING_METHODS.matches(mit)) {
            usageStatusStack.forEach(usageStatus -> usageStatus.addLoggingMethodInvocation(mit));
        }
    }

    @Override
    public void visitMemberSelectExpression(MemberSelectExpressionTree tree) {
        final IdentifierTree identifier;
        ExpressionTree expression = tree.expression();
        if (expression.is(Kind.IDENTIFIER)) {
            identifier = (IdentifierTree) expression;
        } else if (expression.is(Kind.PARENTHESIZED_EXPRESSION) && ((ParenthesizedTree) expression).expression().is(Kind.IDENTIFIER)) {
            identifier = (IdentifierTree) ((ParenthesizedTree) expression).expression();
        } else {
            identifier = null;
        }

        if (!usageStatusStack.isEmpty() && identifier != null) {
            usageStatusStack.forEach(usageStatus -> usageStatus.addInvalidUsage(identifier));
        }
        super.visitMemberSelectExpression(tree);

    }

    private boolean isExcludedType(Tree tree) {
        return isUnqualifiedExcludedType(tree) ||
            isQualifiedExcludedType(tree);
    }

    private boolean isUnqualifiedExcludedType(Tree tree) {
        return tree.is(Kind.IDENTIFIER) &&
            getExceptionIdentifiers().contains(((IdentifierTree) tree).name());
    }

    private boolean isQualifiedExcludedType(Tree tree) {
        if (!tree.is(Kind.MEMBER_SELECT)) {
            return false;
        }
        return getExceptions().contains(ExpressionsHelper.concatenate((MemberSelectExpressionTree) tree));
    }

    private List<String> getExceptions() {
        if (exceptions == null) {
            if ("-".equals(exceptionsCommaSeparated.trim())) {
                // explicitly handle '-' as discarding character
                exceptions = Collections.emptyList();
            } else {
                exceptions = Stream.of(exceptionsCommaSeparated.split(",")).map(String::trim).collect(Collectors.toList());
            }
        }
        return exceptions;
    }

    private List<String> getExceptionIdentifiers() {
        if (exceptionIdentifiers == null) {
            exceptionIdentifiers = getExceptions().stream()
                .map(exception -> exception.substring(exception.lastIndexOf('.') + 1))
                .collect(Collectors.toList());
        }
        return exceptionIdentifiers;
    }

    private static class UsageStatus {
        private final Collection<IdentifierTree> validUsages;
        private final Set<MethodInvocationTree> loggingMethodInvocations;

        UsageStatus(Collection<IdentifierTree> usages) {
            validUsages = new ArrayList<>(usages);
            loggingMethodInvocations = new HashSet<>();
        }

        public void addInvalidUsage(IdentifierTree exceptionIdentifier) {
            validUsages.remove(exceptionIdentifier);
        }

        public void addLoggingMethodInvocation(MethodInvocationTree mit) {
            loggingMethodInvocations.add(mit);
        }

        public boolean isInvalid() {
            return validUsages.isEmpty() && !isMessageLoggedWithAdditionalContext();
        }

        private boolean isMessageLoggedWithAdditionalContext() {
            return loggingMethodInvocations.stream().anyMatch(mit -> hasGetMessageInvocation(mit) && hasDynamicExceptionMessageUsage(mit));
        }

        private static boolean hasGetMessageInvocation(MethodInvocationTree mit) {
            return hasGetMessageMethodInvocation(mit) || isGetMessageReferencedByIdentifiers(mit);
        }

        private static boolean isGetMessageReferencedByIdentifiers(MethodInvocationTree mit) {
            LogExceptionsCorrectlyCheck.ChildrenIdentifierCollector visitor = new LogExceptionsCorrectlyCheck.ChildrenIdentifierCollector();
            mit.accept(visitor);

            boolean invocationInInitializer = visitor.identifiersChildren.stream()
                .map(LogExceptionsCorrectlyCheck.UsageStatus::getVariableInitializer)
                .distinct()
                .anyMatch(LogExceptionsCorrectlyCheck.UsageStatus::hasGetMessageMethodInvocation);

            return invocationInInitializer || visitor.identifiersChildren.stream()
                .map(IdentifierTree::symbol)
                .map(Symbol::usages)
                .flatMap(usagesList -> getAssignments(usagesList).stream())
                .anyMatch(assignment -> hasGetMessageMethodInvocation(assignment.expression()));
        }

        private static boolean hasGetMessageMethodInvocation(@Nullable Tree tree) {
            if (tree == null) {
                return false;
            }
            LogExceptionsCorrectlyCheck.GetExceptionMessageVisitor visitor = new LogExceptionsCorrectlyCheck.GetExceptionMessageVisitor();
            tree.accept(visitor);
            return visitor.hasGetMessageCall;
        }

        private static boolean hasDynamicExceptionMessageUsage(MethodInvocationTree mit) {
            Arguments arguments = mit.arguments();
            int argumentsCount = arguments.size();
            ExpressionTree firstArg = arguments.get(0);
            ExpressionTree argumentToCheck;
            if (mit.symbol().owner().type().is(SLF4J_LOGGER)) {
                if (argumentsCount == 1) {
                    argumentToCheck = firstArg;
                } else if (argumentsCount == 2 && firstArg.symbolType().is("org.slf4j.Marker")) {
                    argumentToCheck = arguments.get(1);
                } else {
                    argumentToCheck = null;
                }
            } else if (JAVA_UTIL_LOG_METHOD.matches(mit) && argumentsCount == 2) {
                argumentToCheck = arguments.get(1);
            } else if (JAVA_UTIL_LOGP_METHOD.matches(mit) && argumentsCount == 4) {
                argumentToCheck = arguments.get(3);
            } else if (JAVA_UTIL_LOGRB_METHOD.matches(mit) && argumentsCount == 5) {
                argumentToCheck = arguments.get(4);
            } else {
                argumentToCheck = firstArg;
            }

            return argumentToCheck == null || !isSimpleExceptionMessage(argumentToCheck);
        }

        private static boolean isSimpleExceptionMessage(ExpressionTree expressionTree) {
            ExpressionTree innerExpression = skipParentheses(expressionTree);
            if (innerExpression.is(Kind.IDENTIFIER)) {
                IdentifierTree variable = (IdentifierTree) innerExpression;
                List<AssignmentExpressionTree> assignments = getAssignments(variable.symbol().usages());
                ExpressionTree initializer = getVariableInitializer(variable);
                return assignments.isEmpty() && initializer != null && isSimpleExceptionMessage(initializer);
            } else if (innerExpression.is(Kind.METHOD_INVOCATION)) {
                return GET_MESSAGE_METHODS.matches(((MethodInvocationTree) innerExpression));
            }
            return false;
        }

        private static List<AssignmentExpressionTree> getAssignments(List<IdentifierTree> usages) {
            return usages.stream().map(LogExceptionsCorrectlyCheck.UsageStatus::getAssignmentToIdentifier).filter(Objects::nonNull).collect(Collectors.toList());
        }

        @CheckForNull
        private static AssignmentExpressionTree getAssignmentToIdentifier(IdentifierTree usage) {
            Tree parent = usage.parent();
            while (parent != null) {
                if (parent.is(Kind.ASSIGNMENT, Kind.PLUS_ASSIGNMENT)) {
                    AssignmentExpressionTree assignmentExpressionTree = (AssignmentExpressionTree) parent;
                    if (assignmentExpressionTree.variable().equals(usage)) {
                        return assignmentExpressionTree;
                    } else {
                        return null;
                    }
                }
                parent = parent.parent();
            }

            return null;
        }

        @CheckForNull
        private static ExpressionTree getVariableInitializer(IdentifierTree variable) {
            Tree declaration = variable.symbol().declaration();
            if (declaration != null && declaration.is(Kind.VARIABLE)) {
                return ((VariableTree) declaration).initializer();
            }
            return null;
        }
    }

    private static class GetExceptionMessageVisitor extends BaseTreeVisitor {
        boolean hasGetMessageCall = false;

        @Override
        public void visitMethodInvocation(MethodInvocationTree mit) {
            if (!hasGetMessageCall && GET_MESSAGE_METHODS.matches(mit)) {
                hasGetMessageCall = true;
            }
            super.visitMethodInvocation(mit);
        }

        @Override
        public void visitNewClass(NewClassTree newClassTree) {
            // skip method invocations found in a NewClassTree
        }
    }

    private static class ChildrenIdentifierCollector extends BaseTreeVisitor {
        Set<IdentifierTree> identifiersChildren = new HashSet<>();

        @Override
        public void visitIdentifier(IdentifierTree tree) {
            identifiersChildren.add(tree);
        }
    }

}
