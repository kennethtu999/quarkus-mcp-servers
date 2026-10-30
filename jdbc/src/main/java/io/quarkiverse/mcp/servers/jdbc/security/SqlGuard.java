package io.quarkiverse.mcp.servers.jdbc.security;

import java.util.List;
import java.util.Locale;
import java.util.Set;

import io.quarkiverse.mcp.servers.jdbc.database.DbDialect;
import io.quarkiverse.mcp.servers.jdbc.database.DbType;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.AnalyticExpression;
import net.sf.jsqlparser.expression.BooleanValue;
import net.sf.jsqlparser.expression.CaseExpression;
import net.sf.jsqlparser.expression.CastExpression;
import net.sf.jsqlparser.expression.DateValue;
import net.sf.jsqlparser.expression.DoubleValue;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.expression.ExtractExpression;
import net.sf.jsqlparser.expression.Function;
import net.sf.jsqlparser.expression.JdbcParameter;
import net.sf.jsqlparser.expression.LongValue;
import net.sf.jsqlparser.expression.NotExpression;
import net.sf.jsqlparser.expression.NullValue;
import net.sf.jsqlparser.expression.Parenthesis;
import net.sf.jsqlparser.expression.SignedExpression;
import net.sf.jsqlparser.expression.StringValue;
import net.sf.jsqlparser.expression.TimeValue;
import net.sf.jsqlparser.expression.TimestampValue;
import net.sf.jsqlparser.expression.WhenClause;
import net.sf.jsqlparser.expression.operators.arithmetic.Addition;
import net.sf.jsqlparser.expression.operators.arithmetic.Concat;
import net.sf.jsqlparser.expression.operators.arithmetic.Division;
import net.sf.jsqlparser.expression.operators.arithmetic.Modulo;
import net.sf.jsqlparser.expression.operators.arithmetic.Multiplication;
import net.sf.jsqlparser.expression.operators.arithmetic.Subtraction;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.expression.operators.conditional.OrExpression;
import net.sf.jsqlparser.expression.operators.relational.Between;
import net.sf.jsqlparser.expression.operators.relational.EqualsTo;
import net.sf.jsqlparser.expression.operators.relational.ExistsExpression;
import net.sf.jsqlparser.expression.operators.relational.ExpressionList;
import net.sf.jsqlparser.expression.operators.relational.GreaterThan;
import net.sf.jsqlparser.expression.operators.relational.GreaterThanEquals;
import net.sf.jsqlparser.expression.operators.relational.InExpression;
import net.sf.jsqlparser.expression.operators.relational.IsNullExpression;
import net.sf.jsqlparser.expression.operators.relational.LikeExpression;
import net.sf.jsqlparser.expression.operators.relational.MinorThan;
import net.sf.jsqlparser.expression.operators.relational.MinorThanEquals;
import net.sf.jsqlparser.expression.operators.relational.NotEqualsTo;
import net.sf.jsqlparser.expression.operators.relational.ParenthesedExpressionList;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.schema.Column;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.statement.Statements;
import net.sf.jsqlparser.statement.select.AllColumns;
import net.sf.jsqlparser.statement.select.AllTableColumns;
import net.sf.jsqlparser.statement.select.ExceptOp;
import net.sf.jsqlparser.statement.select.FromItem;
import net.sf.jsqlparser.statement.select.GroupByElement;
import net.sf.jsqlparser.statement.select.IntersectOp;
import net.sf.jsqlparser.statement.select.Join;
import net.sf.jsqlparser.statement.select.MinusOp;
import net.sf.jsqlparser.statement.select.OrderByElement;
import net.sf.jsqlparser.statement.select.ParenthesedFromItem;
import net.sf.jsqlparser.statement.select.ParenthesedSelect;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;
import net.sf.jsqlparser.statement.select.SelectItem;
import net.sf.jsqlparser.statement.select.SetOperationList;
import net.sf.jsqlparser.statement.select.UnionOp;
import net.sf.jsqlparser.statement.select.WithItem;

/**
 * Decides whether an AI-supplied string is a single, plain, side-effect-free SELECT.
 * <p>
 * This is a <strong>default-deny allowlist</strong>, not a blocklist: every statement clause and every expression node is
 * checked against an explicit list of exact classes, and anything not on it (including node types that did not exist when
 * this was written) is rejected. A parser differential or an unknown dialect feature therefore fails closed.
 * <p>
 * This guard is one layer. The query is also run on a read-only, rolled-back transaction with a timeout, and the database
 * account should only hold SELECT grants (plan section 10.4).
 */
public final class SqlGuard {

    private static final int MAX_LENGTH = 8_192;
    private static final int MAX_DEPTH = 24;
    private static final int MAX_NODES = 2_000;

    /**
     * Oracle and Db2 expose built-in packages as {@code PKG.MEMBER}, which the parser reports as a column qualified by a
     * "table". Rejecting by prefix is a denylist, but it is the only place one is unavoidable; the function allowlist
     * handles everything that parses as a call.
     */
    private static final List<String> BUILTIN_PACKAGE_PREFIXES = List.of("DBMS_", "UTL_", "OWA_", "HTP", "CTX_", "SDO_",
            "XDB", "SYS_", "APEX_", "SYSPROC", "SYSFUN", "SYSIBM");

    /** Bare words that return session or user identity or drive hierarchical queries. */
    private static final Set<String> PSEUDO_COLUMNS_DENIED = Set.of("USER", "SYS_CONTEXT", "SESSION_USER", "CURRENT_USER",
            "SYSTEM_USER", "PRIOR", "CONNECT_BY_ROOT", "SYS_GUID");

    private final DbType type;
    private final Set<String> systemSchemas;

    public SqlGuard(DbType type) {
        this.type = type;
        this.systemSchemas = DbDialect.of(type).systemSchemas();
    }

    public static final class Rejected extends Exception {
        public Rejected(String message) {
            super(message);
        }
    }

    /** Validates {@code sql}; returns normally only for an accepted statement. */
    public void check(String sql) throws Rejected {
        if (sql == null || sql.isBlank()) {
            throw new Rejected("SQL is empty");
        }
        if (sql.length() > MAX_LENGTH) {
            throw new Rejected("SQL is longer than " + MAX_LENGTH + " characters");
        }
        rejectLexicalHazards(sql);

        Statements parsed;
        try {
            parsed = CCJSqlParserUtil.parseStatements(sql);
        } catch (JSQLParserException | RuntimeException | StackOverflowError e) {
            // Never echo the parser message: it quotes the input.
            throw new Rejected("SQL could not be parsed as a supported SELECT");
        }
        if (parsed == null || parsed.size() != 1) {
            throw new Rejected("Exactly one statement is allowed");
        }
        Statement stmt = parsed.get(0);
        if (stmt.getClass() != PlainSelect.class && stmt.getClass() != SetOperationList.class
                && stmt.getClass() != ParenthesedSelect.class) {
            throw new Rejected("Only SELECT statements are allowed");
        }
        try {
            new Walk().select((Select) stmt, 0);
        } catch (Rejected r) {
            throw r;
        } catch (RuntimeException | StackOverflowError e) {
            // A bug or an unexpected parse tree shape must never turn into "allowed".
            throw new Rejected("SQL could not be verified as a supported SELECT");
        }
    }

    /** Checks done on the raw text because they must not depend on the parser agreeing with the database. */
    private static void rejectLexicalHazards(String sql) throws Rejected {
        boolean inString = false;
        boolean inQuotedId = false;
        for (int i = 0; i < sql.length(); i++) {
            char c = sql.charAt(i);
            if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) {
                throw new Rejected("SQL contains control characters");
            }
            if (inString) {
                if (c == '\'') {
                    inString = false;
                }
                continue;
            }
            if (inQuotedId) {
                if (c == '"') {
                    inQuotedId = false;
                }
                continue;
            }
            if (c == '\'') {
                inString = true;
            } else if (c == '"') {
                inQuotedId = true;
            } else if (c == '-' && i + 1 < sql.length() && sql.charAt(i + 1) == '-') {
                throw new Rejected("SQL comments are not allowed");
            } else if (c == '/' && i + 1 < sql.length() && sql.charAt(i + 1) == '*') {
                throw new Rejected("SQL comments and optimizer hints are not allowed");
            } else if (c == '`' || c == '\\') {
                throw new Rejected("Unsupported character in SQL");
            } else if (c == '$' && i + 1 < sql.length()
                    && (sql.charAt(i + 1) == '$' || Character.isLetter(sql.charAt(i + 1)))) {
                throw new Rejected("Dollar quoting is not allowed");
            }
        }
        if (inString || inQuotedId) {
            throw new Rejected("Unterminated string or identifier");
        }
    }

    private final class Walk {
        private int nodes;

        private void tick(int depth) throws Rejected {
            if (depth > MAX_DEPTH) {
                throw new Rejected("SQL is nested too deeply");
            }
            if (++nodes > MAX_NODES) {
                throw new Rejected("SQL is too complex");
            }
        }

        void select(Select s, int depth) throws Rejected {
            tick(depth);
            if (s.getForUpdate() != null || s.getForUpdateTable() != null
                    || (s.getForUpdateTables() != null && !s.getForUpdateTables().isEmpty())
                    || s.getForMode() != null || s.isSkipLocked() || s.getWait() != null || s.isNoWait()) {
                throw new Rejected("Locking clauses (FOR UPDATE and similar) are not allowed");
            }
            if (s.getForClause() != null || s.getOption() != null || s.getIsolation() != null
                    || s.getMySqlProcedureAnalyse() != null || s.getLimitBy() != null || s.getPivot() != null
                    || s.getUnPivot() != null) {
                throw new Rejected("Unsupported SELECT clause");
            }
            if (s.getWithItemsList() != null) {
                for (WithItem<?> w : s.getWithItemsList()) {
                    // A CTE body may be a DML statement in some dialects; WithItem<?> is only accepted for plain selects.
                    if (!(w.getParenthesedStatement() instanceof Select inner)) {
                        throw new Rejected("Only SELECT is allowed inside WITH");
                    }
                    if (w.getWithItemList() != null && !w.getWithItemList().isEmpty()) {
                        throw new Rejected("Unsupported WITH clause");
                    }
                    select(inner, depth + 1);
                }
            }
            if (s.getOrderByElements() != null) {
                for (OrderByElement o : s.getOrderByElements()) {
                    expr(o.getExpression(), depth + 1);
                }
            }
            if (s.getLimit() != null) {
                expr(s.getLimit().getRowCount(), depth + 1);
                expr(s.getLimit().getOffset(), depth + 1);
            }
            if (s.getOffset() != null) {
                expr(s.getOffset().getOffset(), depth + 1);
            }
            if (s.getFetch() != null) {
                expr(s.getFetch().getExpression(), depth + 1);
            }

            Class<?> k = s.getClass();
            if (k == PlainSelect.class) {
                plain((PlainSelect) s, depth);
            } else if (k == SetOperationList.class) {
                SetOperationList list = (SetOperationList) s;
                for (var op : list.getOperations()) {
                    Class<?> oc = op.getClass();
                    if (oc != UnionOp.class && oc != IntersectOp.class && oc != ExceptOp.class && oc != MinusOp.class) {
                        throw new Rejected("Unsupported set operation");
                    }
                }
                for (Select part : list.getSelects()) {
                    select(part, depth + 1);
                }
            } else if (k == ParenthesedSelect.class) {
                select(((ParenthesedSelect) s).getSelect(), depth + 1);
            } else {
                throw new Rejected("Unsupported kind of SELECT");
            }
        }

        void plain(PlainSelect p, int depth) throws Rejected {
            if (p.getIntoTables() != null && !p.getIntoTables().isEmpty() || p.getIntoTempTable() != null
                    || p.getMySqlSelectIntoClause() != null) {
                throw new Rejected("SELECT INTO is not allowed");
            }
            if (p.getOracleHint() != null || p.getOptimizeFor() != null || p.getSampleClause() != null
                    || p.getPreWhere() != null || p.getQualify() != null || p.getTop() != null || p.getSkip() != null
                    || p.getFirst() != null || p.getForXmlPath() != null || p.getKsqlWindow() != null
                    || (p.getEmitMode() != null && p.getEmitMode() != PlainSelect.EmitMode.NONE)
                    || p.getPreferringClause() != null || p.getMySqlHintStraightJoin()
                    || p.getMySqlSqlCalcFoundRows() || p.getMySqlSqlCacheFlag() != null
                    || p.getBigQuerySelectQualifier() != null || p.isUsingFinal() || p.isUseWithNoLog()) {
                throw new Rejected("Unsupported SELECT option");
            }
            if (p.getLateralViews() != null && !p.getLateralViews().isEmpty()) {
                throw new Rejected("LATERAL VIEW is not allowed");
            }
            if (p.getWindowDefinitions() != null && !p.getWindowDefinitions().isEmpty()) {
                throw new Rejected("Named windows are not allowed");
            }
            if (p.getOracleHierarchical() != null) {
                throw new Rejected("Hierarchical queries (CONNECT BY) are not allowed");
            }
            if (p.getSelectItems() == null || p.getSelectItems().isEmpty()) {
                throw new Rejected("SELECT list is empty");
            }
            for (SelectItem<?> item : p.getSelectItems()) {
                tick(depth);
                Expression e = item.getExpression();
                Class<?> ec = e.getClass();
                if (ec == AllColumns.class) {
                    if (((AllColumns) e).getExceptColumns() != null || ((AllColumns) e).getReplaceExpressions() != null) {
                        throw new Rejected("Unsupported use of *");
                    }
                } else if (ec == AllTableColumns.class) {
                    // t.*  - the table part is checked through the FROM item
                    continue;
                } else {
                    expr(e, depth + 1);
                }
            }
            if (p.getFromItem() == null) {
                throw new Rejected("A FROM clause is required");
            }
            fromItem(p.getFromItem(), depth + 1);
            if (p.getJoins() != null) {
                for (Join j : p.getJoins()) {
                    join(j, depth + 1);
                }
            }
            expr(p.getWhere(), depth + 1);
            expr(p.getHaving(), depth + 1);
            if (p.getDistinct() != null && p.getDistinct().getOnSelectItems() != null) {
                throw new Rejected("DISTINCT ON is not allowed");
            }
            GroupByElement g = p.getGroupBy();
            if (g != null) {
                if (g.getGroupingSets() != null && !g.getGroupingSets().isEmpty()) {
                    throw new Rejected("GROUPING SETS are not allowed");
                }
                for (Object ge : g.getGroupByExpressionList()) {
                    expr((Expression) ge, depth + 1);
                }
            }
        }

        void join(Join j, int depth) throws Rejected {
            tick(depth);
            if (j.isApply() || j.isStraight() || j.isGlobal() || j.isArray() || j.isFetch() || j.isAsOf() || j.isWindowJoin()
                    || j.getJoinHint() != null) {
                throw new Rejected("Unsupported join type");
            }
            fromItem(j.getRightItem(), depth + 1);
            for (Expression on : j.getOnExpressions()) {
                expr(on, depth + 1);
            }
        }

        void fromItem(FromItem f, int depth) throws Rejected {
            tick(depth);
            if (f == null) {
                return;
            }
            if (f.getAlias() != null && f.getAlias().getName() == null) {
                throw new Rejected("Unsupported alias");
            }
            Class<?> k = f.getClass();
            if (k == Table.class) {
                table((Table) f);
            } else if (k == ParenthesedSelect.class || k == PlainSelect.class || k == SetOperationList.class) {
                select((Select) f, depth + 1);
            } else if (k == ParenthesedFromItem.class) {
                ParenthesedFromItem pf = (ParenthesedFromItem) f;
                fromItem(pf.getFromItem(), depth + 1);
                if (pf.getJoins() != null) {
                    for (Join j : pf.getJoins()) {
                        join(j, depth + 1);
                    }
                }
            } else {
                // TableFunction, LateralSubSelect, Values, XmlTable, JsonTable, ...
                throw new Rejected("Only tables and sub-selects are allowed in FROM");
            }
        }

        void table(Table t) throws Rejected {
            if (t.getDatabaseName() != null) {
                throw new Rejected("Cross-database references are not allowed");
            }
            String schema = t.getSchemaName();
            if (schema != null && systemSchemas.contains(schema.replace("\"", "").toUpperCase(Locale.ROOT))
                    || schema != null && systemSchemas.contains(schema.replace("\"", ""))) {
                throw new Rejected("System schemas cannot be read");
            }
            String full = t.getFullyQualifiedName() == null ? "" : t.getFullyQualifiedName();
            if (full.indexOf('@') >= 0 || (t.getName() != null && t.getName().indexOf('@') >= 0)) {
                throw new Rejected("Database links are not allowed");
            }
            String name = t.getName() == null ? "" : t.getName().replace("\"", "");
            if (isSystemObjectName(name)) {
                throw new Rejected("System catalog objects cannot be read");
            }
            if (t.getPivot() != null || t.getUnPivot() != null || t.getSampleClause() != null || t.getIndexHint() != null
                    || t.getSqlServerHints() != null) {
                throw new Rejected("Unsupported table option");
            }
        }

        void expr(Expression e, int depth) throws Rejected {
            if (e == null) {
                return;
            }
            tick(depth);
            Class<?> k = e.getClass();

            if (isLeaf(k)) {
                return;
            }
            if (k == Column.class) {
                column((Column) e);
                return;
            }
            if (k == Parenthesis.class) {
                expr(((Parenthesis) e).getExpression(), depth + 1);
            } else if (k == NotExpression.class) {
                expr(((NotExpression) e).getExpression(), depth + 1);
            } else if (k == SignedExpression.class) {
                expr(((SignedExpression) e).getExpression(), depth + 1);
            } else if (isBinary(k)) {
                var b = (net.sf.jsqlparser.expression.BinaryExpression) e;
                if (b instanceof net.sf.jsqlparser.expression.operators.relational.SupportsOldOracleJoinSyntax old
                        && (old.getOldOracleJoinSyntax() != 0 || old.getOraclePriorPosition() != 0)) {
                    throw new Rejected("Oracle PRIOR and (+) join syntax are not allowed");
                }
                expr(b.getLeftExpression(), depth + 1);
                expr(b.getRightExpression(), depth + 1);
            } else if (k == IsNullExpression.class) {
                expr(((IsNullExpression) e).getLeftExpression(), depth + 1);
            } else if (k == Between.class) {
                Between b = (Between) e;
                expr(b.getLeftExpression(), depth + 1);
                expr(b.getBetweenExpressionStart(), depth + 1);
                expr(b.getBetweenExpressionEnd(), depth + 1);
            } else if (k == InExpression.class) {
                InExpression in = (InExpression) e;
                if (in.getOldOracleJoinSyntax() != 0 || in.getOraclePriorPosition() != 0) {
                    throw new Rejected("Unsupported IN syntax");
                }
                expr(in.getLeftExpression(), depth + 1);
                expr(in.getRightExpression(), depth + 1);
            } else if (k == ExistsExpression.class) {
                expr(((ExistsExpression) e).getRightExpression(), depth + 1);
            } else if (k == ExpressionList.class || k == ParenthesedExpressionList.class) {
                for (Object item : (List<?>) e) {
                    expr((Expression) item, depth + 1);
                }
            } else if (k == CaseExpression.class) {
                CaseExpression c = (CaseExpression) e;
                expr(c.getSwitchExpression(), depth + 1);
                if (c.getWhenClauses() != null) {
                    for (WhenClause w : c.getWhenClauses()) {
                        expr(w.getWhenExpression(), depth + 1);
                        expr(w.getThenExpression(), depth + 1);
                    }
                }
                expr(c.getElseExpression(), depth + 1);
            } else if (k == CastExpression.class) {
                CastExpression c = (CastExpression) e;
                expr(c.getLeftExpression(), depth + 1);
            } else if (k == ExtractExpression.class) {
                expr(((ExtractExpression) e).getExpression(), depth + 1);
            } else if (k == Function.class) {
                function((Function) e, depth);
            } else if (k == AnalyticExpression.class) {
                analytic((AnalyticExpression) e, depth);
            } else if (k == PlainSelect.class || k == SetOperationList.class || k == ParenthesedSelect.class) {
                select((Select) e, depth + 1);
            } else {
                throw new Rejected("Unsupported SQL construct: " + k.getSimpleName());
            }
        }

        void function(Function f, int depth) throws Rejected {
            String name = f.getName();
            if (!FunctionAllowlists.allowed(type, name)) {
                throw new Rejected("Function " + abbreviate(name) + " is not allowed");
            }
            if (f.getNamedParameters() != null || f.getOrderByElements() != null
                    || f.getAttribute() != null || f.getAttributeColumn() != null || f.getOnOverflowTruncate() != null) {
                throw new Rejected("Unsupported function syntax");
            }
            if (f.getParameters() != null) {
                for (Object p : f.getParameters()) {
                    Expression arg = (Expression) p;
                    if (arg.getClass() == AllColumns.class) {
                        continue; // COUNT(*)
                    }
                    expr(arg, depth + 1);
                }
            }
        }

        void column(Column c) throws Rejected {
            String col = c.getColumnName() == null ? "" : c.getColumnName().replace("\"", "");
            String upper = col.toUpperCase(Locale.ROOT);
            if (upper.equals("NEXTVAL") || upper.equals("CURRVAL")) {
                throw new Rejected("Sequences cannot be used");
            }
            if (PSEUDO_COLUMNS_DENIED.contains(upper)) {
                throw new Rejected("Reserved name " + upper + " cannot be used");
            }
            Table q = c.getTable();
            if (q != null) {
                if (q.getDatabaseName() != null) {
                    throw new Rejected("Cross-database references are not allowed");
                }
                String schema = q.getSchemaName() == null ? null : q.getSchemaName().replace("\"", "").toUpperCase(Locale.ROOT);
                if (schema != null && systemSchemas.contains(schema)) {
                    throw new Rejected("System schemas cannot be read");
                }
                String qualifier = q.getName() == null ? "" : q.getName().replace("\"", "").toUpperCase(Locale.ROOT);
                for (String prefix : BUILTIN_PACKAGE_PREFIXES) {
                    if (qualifier.startsWith(prefix) || (schema != null && schema.startsWith(prefix))) {
                        throw new Rejected("Built-in packages cannot be used");
                    }
                }
            }
        }

        void analytic(AnalyticExpression a, int depth) throws Rejected {
            if (!FunctionAllowlists.allowed(type, a.getName())) {
                throw new Rejected("Function " + abbreviate(a.getName()) + " is not allowed");
            }
            if (a.getKeep() != null || a.getFilterExpression() != null || a.getWindowName() != null) {
                throw new Rejected("Unsupported window function syntax");
            }
            expr(a.getExpression(), depth + 1);
            expr(a.getOffset(), depth + 1);
            expr(a.getDefaultValue(), depth + 1);
            if (a.getPartitionExpressionList() != null) {
                for (Object p : a.getPartitionExpressionList()) {
                    expr((Expression) p, depth + 1);
                }
            }
            if (a.getOrderByElements() != null) {
                for (OrderByElement o : a.getOrderByElements()) {
                    expr(o.getExpression(), depth + 1);
                }
            }
        }
    }

    private static boolean isLeaf(Class<?> k) {
        return k == LongValue.class || k == DoubleValue.class || k == StringValue.class || k == NullValue.class
                || k == BooleanValue.class || k == DateValue.class || k == TimeValue.class || k == TimestampValue.class
                || k == JdbcParameter.class;
    }

    private static boolean isBinary(Class<?> k) {
        return k == AndExpression.class || k == OrExpression.class || k == EqualsTo.class || k == NotEqualsTo.class
                || k == GreaterThan.class || k == GreaterThanEquals.class || k == MinorThan.class
                || k == MinorThanEquals.class || k == LikeExpression.class || k == Addition.class
                || k == Subtraction.class || k == Multiplication.class || k == Division.class || k == Modulo.class
                || k == Concat.class;
    }

    private boolean isSystemObjectName(String name) {
        String n = name.toUpperCase(Locale.ROOT);
        return switch (type) {
            case POSTGRESQL -> n.startsWith("PG_") || n.equals("INFORMATION_SCHEMA");
            case DB2_LUW -> n.startsWith("SYSCAT") || n.startsWith("SYSIBM") || n.startsWith("SYSSTAT");
            case ORACLE -> n.startsWith("V$") || n.startsWith("GV$") || n.startsWith("DBA_") || n.startsWith("ALL_")
                    || n.startsWith("USER_") || n.startsWith("DICT") || n.equals("DUAL_NOT_ALLOWED");
        };
    }

    private static String abbreviate(String s) {
        if (s == null) {
            return "?";
        }
        return s.length() <= 40 ? s : s.substring(0, 40) + "...";
    }
}
